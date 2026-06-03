// Copyright (c) 2026 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

#![allow(missing_docs)]

use log::*;
use tdx::launch::TdxCapabilities;
use threadpool::ThreadPool;
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemoryMmap};

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, RwLock};

pub const TDX_GET_QUOTE_STRUCTURE_VERSION: u64 = 1;
pub const TDX_GET_QUOTE_BUF_ALIGN: u64 = 4096;

pub const TDX_GET_QUOTE_MAX_BUF_LEN: u64 = 128 * 1024;
pub const TDX_GET_QUOTE_MAX_REQUEST: usize = 16;

pub const TDX_GET_QUOTE_HDR_SIZE: u64 = core::mem::size_of::<TdxGetQuoteHeader>() as u64;

pub const TDG_VP_VMCALL_SUCCESS: u64 = 0;
pub const TDG_VP_VMCALL_RETRY: u64 = 1;
pub const TDG_VP_VMCALL_INVALID_OPERAND: u64 = 0x8000000000000000;
pub const TDG_VP_VMCALL_ALIGN_ERROR: u64 = 0x8000000000000002;

pub const TDX_VP_GET_QUOTE_QGS_UNAVAILABLE: u64 = 0x8000000000000001;

pub const TDG_VP_VMCALL_SUBFUNC_SET_EVENT_NOTIFY_INTERRUPT: u64 = 1 << 1;

pub const SUPPORTED_TDVMCALLINFO_1_R11: u64 = TDG_VP_VMCALL_SUBFUNC_SET_EVENT_NOTIFY_INTERRUPT;
pub const SUPPORTED_TDVMCALLINFO_1_R12: u64 = 0;

pub const QGS_MSG_LIB_MAJOR_VER: u16 = 1;
pub const QGS_MSG_LIB_MINOR_VER: u16 = 1;

pub const QGS_MSG_TYPE_GET_QUOTE_REQ: u32 = 0;
pub const QGS_MSG_TYPE_GET_QUOTE_RESP: u32 = 1;

const HEADER_SIZE: usize = 4;

#[repr(C)]
#[derive(Default, Debug)]
pub struct TdxGetTdvmcallInfo {
    pub ret: u64,
    pub leaf: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
}

#[repr(C)]
#[derive(Default, Debug)]
pub struct TdxSetupEventNotify {
    pub ret: u64,
    pub vector: u64,
}

#[repr(C)]
#[derive(Default, Debug)]
pub struct TdxGetQuote {
    pub ret: u64,
    pub gpa: u64,
    pub size: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct TdxGetQuoteHeader {
    pub structure_version: u64,
    pub error_code: u64,
    pub in_len: u32,
    pub out_len: u32,
}

unsafe impl ByteValued for TdxGetQuoteHeader {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct QgsMessageHeader {
    pub major_version: u16,
    pub minor_version: u16,
    pub r#type: u32,
    pub size: u32,
    pub error_code: u32,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct QgsMessageGetQuoteReq {
    pub header: QgsMessageHeader,
    pub report_size: u32,
    pub id_list_size: u32,
}

unsafe impl ByteValued for QgsMessageHeader {}
unsafe impl ByteValued for QgsMessageGetQuoteReq {}

/// Handler for VCPU exit type: KVM_EXIT_TDX
pub struct TdxExitHandler<'a> {
    quote_generation_socket: Option<String>,
    thread_pool: ThreadPool,
    event_notify_vector: Arc<RwLock<u8>>,
    tdx_capabilities: Arc<TdxCapabilities>,
    mem: &'a GuestMemoryMmap,
}

impl<'a> TdxExitHandler<'a> {
    pub fn new(
        quote_generation_socket: Option<String>,
        tdx_capabilities: Arc<TdxCapabilities>,
        mem: &'a GuestMemoryMmap,
    ) -> Self {
        Self {
            quote_generation_socket,
            tdx_capabilities,
            mem,
            thread_pool: ThreadPool::with_name(
                "tdxquote-thread".to_string(),
                TDX_GET_QUOTE_MAX_REQUEST,
            ),
            event_notify_vector: Arc::new(RwLock::new(0)),
        }
    }

    pub fn handle_get_tdvmcall_info(&self, get_tdvmcall_info: &mut TdxGetTdvmcallInfo) {
        if get_tdvmcall_info.leaf != 1 {
            return;
        }

        get_tdvmcall_info.r11 = (self.tdx_capabilities.user_tdvmcallinfo_1_r11
            & SUPPORTED_TDVMCALLINFO_1_R11)
            | self.tdx_capabilities.kernel_tdvmcallinfo_1_r11;
        get_tdvmcall_info.r12 = (self.tdx_capabilities.user_tdvmcallinfo_1_r12
            & SUPPORTED_TDVMCALLINFO_1_R12)
            | self.tdx_capabilities.kernel_tdvmcallinfo_1_r12;
        get_tdvmcall_info.r13 = 0;
        get_tdvmcall_info.r14 = 0;

        get_tdvmcall_info.ret = TDG_VP_VMCALL_SUCCESS;
    }

    pub fn handle_setup_event_notify_interrupt(
        &self,
        setup_event_notify: &mut TdxSetupEventNotify,
    ) {
        let vector = setup_event_notify.vector;
        if vector >= 32 && vector < 256 {
            *self.event_notify_vector.write().unwrap() = vector as u8;
            setup_event_notify.ret = TDG_VP_VMCALL_SUCCESS;
        } else {
            setup_event_notify.ret = TDG_VP_VMCALL_INVALID_OPERAND;
        }
    }

    pub fn handle_get_quote(&self, get_quote: &mut TdxGetQuote) {
        let buf_gpa = get_quote.gpa;
        let buf_len = get_quote.size;

        get_quote.ret = TDG_VP_VMCALL_INVALID_OPERAND;

        if buf_len == 0 {
            return;
        }

        if buf_gpa % TDX_GET_QUOTE_BUF_ALIGN != 0 || buf_len % TDX_GET_QUOTE_BUF_ALIGN != 0 {
            get_quote.ret = TDG_VP_VMCALL_ALIGN_ERROR;
            return;
        }

        let mut header: TdxGetQuoteHeader = match self.mem.read_obj(GuestAddress(buf_gpa)) {
            Ok(hdr) => hdr,
            Err(_) => {
                error!("TDX GetQuote: Failed to read GetQuote header");
                return;
            }
        };

        if header.structure_version != TDX_GET_QUOTE_STRUCTURE_VERSION {
            return;
        }

        if buf_len > TDX_GET_QUOTE_MAX_BUF_LEN
            || header.in_len as u64 > buf_len - TDX_GET_QUOTE_HDR_SIZE
        {
            return;
        }

        if self.quote_generation_socket.is_none() {
            header.error_code = TDX_VP_GET_QUOTE_QGS_UNAVAILABLE;
            if self.mem.write_obj(header, GuestAddress(buf_gpa)).is_err() {
                error!("TDX GetQuote: Failed to update GetQuote header");
                return;
            }
            get_quote.ret = TDG_VP_VMCALL_SUCCESS;
            return;
        }

        if self.thread_pool.active_count() >= TDX_GET_QUOTE_MAX_REQUEST {
            get_quote.ret = TDG_VP_VMCALL_RETRY;
            return;
        }

        let mut report_data = Vec::with_capacity(header.in_len as usize);
        report_data.resize(header.in_len as usize, 0u8);
        if self
            .mem
            .read_slice(
                report_data.as_mut_slice(),
                GuestAddress(buf_gpa + TDX_GET_QUOTE_HDR_SIZE),
            )
            .is_err()
        {
            error!("TDX GetQuote: Failed to read report data");
            return;
        }
    }

    fn generate_quote(&self, report_data: Vec<u8>) -> Result<Vec<u8>, std::io::Error> {
        let message_size =
            (core::mem::size_of::<QgsMessageGetQuoteReq>() + report_data.len()) as u32;
        let message = QgsMessageGetQuoteReq {
            header: QgsMessageHeader {
                major_version: QGS_MSG_LIB_MAJOR_VER,
                minor_version: QGS_MSG_LIB_MINOR_VER,
                r#type: QGS_MSG_TYPE_GET_QUOTE_REQ,
                size: message_size,
                error_code: 0,
            },
            report_size: report_data.len() as u32,
            id_list_size: 0,
        };

        // Length prefix
        let header = encode_header(message_size);

        let mut stream = UnixStream::connect(self.quote_generation_socket.as_ref().unwrap())?;

        stream.write_all(&header)?;
        stream.write_all(message.as_slice())?;
        stream.write_all(report_data.as_slice())?;
        stream.flush()?;

        Ok(Vec::new())
    }
}

fn encode_header(size: u32) -> [u8; HEADER_SIZE] {
    size.to_be_bytes()
}
