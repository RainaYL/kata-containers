// Copyright (C) 2023 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::fd::RawFd;

use kvm_bindings::{CpuId, KVMIO};
use kvm_ioctls::Cap;
use vmm_sys_util::ioctl::ioctl_with_val;
use vmm_sys_util::{ioctl_io_nr, ioctl_ioc_nr};

#[cfg(target_arch = "x86_64")]
pub mod tdx_ioctls;
pub use tdx_ioctls::*;

#[cfg(target_arch = "x86_64")]
pub mod td_shim;

pub const KVM_X86_TDX_VM: u64 = 5;

pub const KVM_CAP_VM_TYPES: u64 = 235;

pub const KVM_TDX_MEASURE_MEMORY_REGION: u32 = 1u32 << 0;

ioctl_io_nr!(KVM_CHECK_EXTENSION, KVMIO, 0x03);

pub fn is_tdx_supported(kvm_fd: &RawFd) -> bool {
    let supported_vm_types =
        unsafe { ioctl_with_val(kvm_fd, KVM_CHECK_EXTENSION(), KVM_CAP_VM_TYPES) } as u64;
    supported_vm_types & (1 << KVM_X86_TDX_VM) > 0
}

pub fn get_max_vcpus(vm_fd: &RawFd) -> usize {
    unsafe { ioctl_with_val(vm_fd, KVM_CHECK_EXTENSION(), Cap::MaxVcpus as u64) as usize }
}

pub fn filter_tdx_cpuid(tdx_supported_cpuid: &CpuId, cpu_id: &mut CpuId) {
    let mut filtered_entries = Vec::new();
    let cpu_id = cpu_id.as_mut_fam_struct();
    unsafe {
        let entries = cpu_id.entries.as_mut_slice(cpu_id.nent as usize);
        for entry in entries.iter() {
            let tdx_entry = find_cpuid_entry(tdx_supported_cpuid, entry.function, entry.index);
            if tdx_entry.is_none() {
                continue;
            }

            let tdx_entry = tdx_entry.unwrap();
            let filtered_entry = kvm_bindings::kvm_cpuid_entry2 {
                function: entry.function,
                index: entry.index,
                flags: entry.flags,
                eax: entry.eax & tdx_entry.eax,
                ebx: entry.ebx & tdx_entry.ebx,
                ecx: entry.ecx & tdx_entry.ecx,
                edx: entry.edx & tdx_entry.edx,
                ..Default::default()
            };
            filtered_entries.push(filtered_entry);
        }

        for (i, entry) in filtered_entries.iter().enumerate() {
            entries[i] = *entry;
        }
        cpu_id.nent = filtered_entries.len() as u32;
    }
}

fn find_cpuid_entry(cpuid: &CpuId, function: u32, index: u32) -> Option<kvm_bindings::kvm_cpuid_entry2> {
    let cpuid = cpuid.as_fam_struct_ref();
    unsafe {
        let entries = cpuid.entries.as_slice(cpuid.nent as usize);
        for entry in entries {
            if entry.function == function && entry.index == index {
                return Some(entry.clone());
            }
        }
    }
    None
}
