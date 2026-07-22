#![allow(missing_docs)]

use std::sync::{Arc, RwLock};

use kvm_ioctls::VmFd;
use log::*;
use tdx::launch::TdxCapabilities;
use threadpool::ThreadPool;
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemoryMmap};

pub const TDX_GET_QUOTE_STRUCTURE_VERSION: u64 = 1;
pub const TDX_GET_QUOTE_BUF_ALIGN: u64 = 4096;

pub const TDX_GET_QUOTE_MAX_BUF_LEN: u64 = 128 * 1024;
pub const TDX_GET_QUOTE_MAX_REQUEST: usize = 16;

pub const TDX_GET_QUOTE_HDR_SIZE: u64 = core::mem::size_of::<TdxGetQuoteHeader>() as u64;

pub const TDG_VP_VMCALL_SUCCESS: u64 = 0;
pub const TDG_VP_VMCALL_RETRY: u64 = 1;
pub const TDG_VP_VMCALL_INVALID_OPERAND: u64 = 0x8000000000000000;
pub const TDG_VP_VMCALL_ALIGN_ERROR: u64 = 0x8000000000000002;

pub const TDX_VP_GET_QUOTE_IN_FLIGHT: u64 = u64::MAX;
pub const TDX_VP_GET_QUOTE_QGS_UNAVAILABLE: u64 = 0x8000000000000001;

pub const TDG_VP_VMCALL_SUBFUNC_SET_EVENT_NOTIFY_INTERRUPT: u64 = 1 << 1;

pub const SUPPORTED_TDVMCALLINFO_1_R11: u64 = TDG_VP_VMCALL_SUBFUNC_SET_EVENT_NOTIFY_INTERRUPT;
pub const SUPPORTED_TDVMCALLINFO_1_R12: u64 = 0;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct TdxGetQuoteHeader {
    pub structure_version: u64,
    pub error_code: u64,
    pub in_len: u32,
    pub out_len: u32,
}

unsafe impl ByteValued for TdxGetQuoteHeader {}

pub struct TdxExitHandler {
    vm_fd: Arc<VmFd>,
    quote_generation_socket: Option<String>,
    thread_pool: ThreadPool,
    event_notify_vector: Arc<RwLock<Option<u8>>>,
    tdx_capabilities: Arc<TdxCapabilities>,
    mem: GuestMemoryMmap,
}

impl TdxExitHandler {
    pub fn new(
        vm_fd: Arc<VmFd>,
        quote_generation_socket: Option<String>,
        tdx_capabilities: Arc<TdxCapabilities>,
        mem: &GuestMemoryMmap,
    ) -> Self {
        Self {
            vm_fd,
            quote_generation_socket,
            tdx_capabilities,
            mem: mem.clone(),
            thread_pool: ThreadPool::with_name(
                "tdxquote-thread".to_string(),
                TDX_GET_QUOTE_MAX_REQUEST,
            ),
            event_notify_vector: Arc::new(RwLock::new(None)),
        }
    }

    pub fn handle_get_tdvmcall_info(
        &self,
        ret: &mut u64,
        leaf: u64,
        r11: &mut u64,
        r12: &mut u64,
        r13: &mut u64,
        r14: &mut u64,
    ) {
        if leaf != 1 {
            return;
        }

        *r11 = (self.tdx_capabilities.user_tdvmcallinfo_1_r11 & SUPPORTED_TDVMCALLINFO_1_R11)
            | self.tdx_capabilities.kernel_tdvmcallinfo_1_r11;
        *r12 = (self.tdx_capabilities.user_tdvmcallinfo_1_r12 & SUPPORTED_TDVMCALLINFO_1_R12)
            | self.tdx_capabilities.kernel_tdvmcallinfo_1_r12;
        *r13 = 0;
        *r14 = 0;

        *ret = TDG_VP_VMCALL_SUCCESS;
    }

    pub fn handle_setup_event_notify_interrupt(&self, ret: &mut u64, vector: u64) {
        if vector >= 32 && vector < 256 {
            *self.event_notify_vector.write().unwrap() = Some(vector as u8);
            *ret = TDG_VP_VMCALL_SUCCESS;
        } else {
            *ret = TDG_VP_VMCALL_INVALID_OPERAND;
        }
    }

    pub fn handle_get_quote(&self, ret: &mut u64, buf_gpa: u64, buf_len: u64) {
        *ret = TDG_VP_VMCALL_INVALID_OPERAND;

        if buf_len == 0 {
            return;
        }

        if buf_gpa % TDX_GET_QUOTE_BUF_ALIGN != 0 || buf_len % TDX_GET_QUOTE_BUF_ALIGN != 0 {
            *ret = TDG_VP_VMCALL_ALIGN_ERROR;
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
            *ret = TDG_VP_VMCALL_SUCCESS;
            return;
        }

        if self.thread_pool.active_count() >= TDX_GET_QUOTE_MAX_REQUEST {
            *ret = TDG_VP_VMCALL_RETRY;
            return;
        }

        let mut report_data = vec![0u8; header.in_len as usize];
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

        let vm_fd = self.vm_fd.clone();
        let vector = *self.event_notify_vector.read().unwrap();
        let quote_generation_socket = self.quote_generation_socket.clone().unwrap();
        let mem = self.mem.clone();

        // self.thread_pool.execute(move || {
        //     Self::async_get_quote(
        //         header,
        //         buf_gpa,
        //         buf_len,
        //         report_data,
        //         vm_fd,
        //         vector,
        //         quote_generation_socket,
        //         mem,
        //     )
        // });

        header.error_code = TDX_VP_GET_QUOTE_IN_FLIGHT;
        if self.mem.write_obj(header, GuestAddress(buf_gpa)).is_err() {
            return;
        }

        *ret = TDG_VP_VMCALL_SUCCESS;
    }
}
