// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use kvm_bindings::*;
use libc::EINVAL;
use std::fs::File;
use std::os::unix::io::{AsRawFd, RawFd, FromRawFd};
use std::os::raw::c_ulong;

use kvm_ioctls::*;
use vmm_sys_util::errno;
use vmm_sys_util::ioctl::{ioctl, ioctl_with_mut_ref, ioctl_with_ref};
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use vmm_sys_util::ioctl::{ioctl_with_mut_ptr, ioctl_with_ptr, ioctl_with_val};
use vmm_sys_util::{ioctl_io_nr, ioctl_ioc_nr, ioctl_ior_nr, ioctl_iow_nr, ioctl_iowr_nr};

pub type Result<T> = std::result::Result<T, errno::Error>;
ioctl_ior_nr!(KVM_GET_REGS, KVMIO, 0x81, kvm_regs);
ioctl_iow_nr!(KVM_SET_REGS, KVMIO, 0x82, kvm_regs);
ioctl_ior_nr!(KVM_GET_SREGS, KVMIO, 0x83, kvm_sregs);
ioctl_iow_nr!(KVM_SET_SREGS, KVMIO, 0x84, kvm_sregs);
ioctl_ior_nr!(KVM_GET_FPU, KVMIO, 0x8c, kvm_fpu);
ioctl_iow_nr!(KVM_SET_FPU, KVMIO, 0x8d, kvm_fpu);
ioctl_iow_nr!(KVM_SET_CPUID2, KVMIO, 0x90, kvm_cpuid2);
ioctl_iowr_nr!(KVM_GET_CPUID2, KVMIO, 0x91, kvm_cpuid2);
ioctl_iow_nr!(KVM_ENABLE_CAP, KVMIO, 0xa3, kvm_enable_cap);
ioctl_ior_nr!(KVM_GET_LAPIC, KVMIO, 0x8e, kvm_lapic_state);
ioctl_iow_nr!(KVM_SET_LAPIC, KVMIO, 0x8f, kvm_lapic_state);
ioctl_iowr_nr!(KVM_GET_MSRS, KVMIO, 0x88, kvm_msrs);
ioctl_iow_nr!(KVM_SET_MSRS, KVMIO, 0x89, kvm_msrs);
ioctl_ior_nr!(KVM_GET_MP_STATE, KVMIO, 0x98, kvm_mp_state);
ioctl_iow_nr!(KVM_SET_MP_STATE, KVMIO, 0x99, kvm_mp_state);
ioctl_ior_nr!(KVM_GET_XSAVE, KVMIO, 0xa4, kvm_xsave);
ioctl_iow_nr!(KVM_SET_XSAVE, KVMIO, 0xa5, kvm_xsave);
ioctl_ior_nr!(KVM_GET_XCRS, KVMIO, 0xa6, kvm_xcrs);
ioctl_iow_nr!(KVM_SET_XCRS, KVMIO, 0xa7, kvm_xcrs);
ioctl_ior_nr!(KVM_GET_DEBUGREGS, KVMIO, 0xa1, kvm_debugregs);
ioctl_iow_nr!(KVM_SET_DEBUGREGS, KVMIO, 0xa2, kvm_debugregs);
ioctl_ior_nr!(KVM_GET_VCPU_EVENTS, KVMIO, 0x9f, kvm_vcpu_events);
ioctl_iow_nr!(KVM_SET_VCPU_EVENTS, KVMIO, 0xa0, kvm_vcpu_events);
ioctl_iow_nr!(KVM_SET_GUEST_DEBUG, KVMIO, 0x9b, kvm_guest_debug);
ioctl_io_nr!(KVM_KVMCLOCK_CTRL, KVMIO, 0xad);
ioctl_io_nr!(KVM_RUN, KVMIO, 0x80);
ioctl_io_nr!(KVM_GET_TSC_KHZ, KVMIO, 0xa3);
ioctl_io_nr!(KVM_SET_TSC_KHZ, KVMIO, 0xa2);
ioctl_iowr_nr!(KVM_TRANSLATE, KVMIO, 0x85, kvm_translation);
ioctl_io_nr!(KVM_CREATE_VCPU, KVMIO, 0x41);

/// Information about a [`VcpuExit`] triggered by an Hypercall (`KVM_EXIT_HYPERCALL`).
#[derive(Debug)]
pub struct HypercallExit<'a> {
    /// The hypercall number.
    pub nr: u64,
    /// The arguments for the hypercall.
    pub args: [u64; 6],
    /// The return code to be indicated to the guest.
    pub ret: &'a mut u64,
    /// Whether the hypercall was executed in long mode.
    pub longmode: u32,
}

/// Reasons for vCPU exits.
///
/// The exit reasons are mapped to the `KVM_EXIT_*` defines in the
/// [Linux KVM header](https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/kvm.h).
#[derive(Debug)]
pub enum VcpuExit<'a> {
    /// An out port instruction was run on the given port with the given data.
    IoOut(u16 /* port */, &'a [u8] /* data */),
    /// An in port instruction was run on the given port.
    ///
    /// The given slice should be filled in before [run()](struct.VcpuFd.html#method.run)
    /// is called again.
    IoIn(u16 /* port */, &'a mut [u8] /* data */),
    /// A read instruction was run against the given MMIO address.
    ///
    /// The given slice should be filled in before [run()](struct.VcpuFd.html#method.run)
    /// is called again.
    MmioRead(u64 /* address */, &'a mut [u8]),
    /// A write instruction was run against the given MMIO address with the given data.
    MmioWrite(u64 /* address */, &'a [u8]),
    /// Corresponds to KVM_EXIT_UNKNOWN.
    Unknown,
    /// Corresponds to KVM_EXIT_EXCEPTION.
    Exception,
    /// Corresponds to KVM_EXIT_HYPERCALL.
    Hypercall(HypercallExit<'a>),
    /// Corresponds to KVM_EXIT_DEBUG.
    ///
    /// Provides architecture specific information for the debug event.
    Debug(kvm_debug_exit_arch),
    /// Corresponds to KVM_EXIT_HLT.
    Hlt,
    /// Corresponds to KVM_EXIT_IRQ_WINDOW_OPEN.
    IrqWindowOpen,
    /// Corresponds to KVM_EXIT_SHUTDOWN.
    Shutdown,
    /// Corresponds to KVM_EXIT_FAIL_ENTRY.
    FailEntry(
        u64, /* hardware_entry_failure_reason */
        u32, /* cpu */
    ),
    /// Corresponds to KVM_EXIT_INTR.
    Intr,
    /// Corresponds to KVM_EXIT_SET_TPR.
    SetTpr,
    /// Corresponds to KVM_EXIT_TPR_ACCESS.
    TprAccess,
    /// Corresponds to KVM_EXIT_S390_SIEIC.
    S390Sieic,
    /// Corresponds to KVM_EXIT_S390_RESET.
    S390Reset,
    /// Corresponds to KVM_EXIT_DCR.
    Dcr,
    /// Corresponds to KVM_EXIT_NMI.
    Nmi,
    /// Corresponds to KVM_EXIT_INTERNAL_ERROR.
    InternalError,
    /// Corresponds to KVM_EXIT_OSI.
    Osi,
    /// Corresponds to KVM_EXIT_PAPR_HCALL.
    PaprHcall,
    /// Corresponds to KVM_EXIT_S390_UCONTROL.
    S390Ucontrol,
    /// Corresponds to KVM_EXIT_WATCHDOG.
    Watchdog,
    /// Corresponds to KVM_EXIT_S390_TSCH.
    S390Tsch,
    /// Corresponds to KVM_EXIT_EPR.
    Epr,
    /// Corresponds to KVM_EXIT_SYSTEM_EVENT.
    SystemEvent(u32 /* type */, u64 /* flags */),
    /// Corresponds to KVM_EXIT_S390_STSI.
    S390Stsi,
    /// Corresponds to KVM_EXIT_IOAPIC_EOI.
    IoapicEoi(u8 /* vector */),
    /// Corresponds to KVM_EXIT_HYPERV.
    Hyperv,
    /// Corresponds to an exit reason that is unknown from the current version
    /// of the kvm-ioctls crate. Let the consumer decide about what to do with
    /// it.
    Unsupported(u32),
}

/// Wrapper over KVM vCPU ioctls.
#[derive(Debug)]
pub struct VcpuFd {
    vcpu: File,
    kvm_run_ptr: KvmRunWrapper,
}

/// KVM Sync Registers used to tell KVM which registers to sync
#[repr(u32)]
#[derive(Debug, Copy, Clone)]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub enum SyncReg {
    /// General purpose registers,
    Register = KVM_SYNC_X86_REGS,

    /// System registers
    SystemRegister = KVM_SYNC_X86_SREGS,

    /// CPU events
    VcpuEvents = KVM_SYNC_X86_EVENTS,
}

impl VcpuFd {
    pub fn new(vm_fd: &VmFd, id: u64) -> Result<Self> {
        // Safe because we know that vm is a VM fd and we verify the return result.
        #[allow(clippy::cast_lossless)]
        let vcpu_fd = unsafe { ioctl_with_val(&vm_fd.as_raw_fd(), KVM_CREATE_VCPU(), id as c_ulong) };
        if vcpu_fd < 0 {
            return Err(errno::Error::last());
        }

        // Wrap the vCPU now in case the following ? returns early. This is safe because we verified
        // the value of the fd and we own the fd.
        let vcpu = unsafe { File::from_raw_fd(vcpu_fd) };

        let kvm_run_ptr = KvmRunWrapper::mmap_from_fd(&vcpu, vm_fd.run_size())?;

        Ok(new_vcpu(vcpu, kvm_run_ptr))
    }

    /// Returns the vCPU general purpose registers.
    ///
    /// The registers are returned in a `kvm_regs` structure as defined in the
    /// [KVM API documentation](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    /// See documentation for `KVM_GET_REGS`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    /// let regs = vcpu.get_regs().unwrap();
    /// ```
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn get_regs(&self) -> Result<kvm_regs> {
        // Safe because we know that our file is a vCPU fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let mut regs = unsafe { std::mem::zeroed() };
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_REGS(), &mut regs) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(regs)
    }

    /// Sets a specified piece of cpu configuration and/or state.
    ///
    /// See the documentation for `KVM_SET_DEVICE_ATTR` in
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt)
    /// # Arguments
    ///
    /// * `device_attr` - The cpu attribute to be set.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_ioctls::Kvm;
    /// # use kvm_bindings::{
    ///    KVM_ARM_VCPU_PMU_V3_CTRL, KVM_ARM_VCPU_PMU_V3_INIT
    /// };
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    ///
    /// let dist_attr = kvm_bindings::kvm_device_attr {
    ///     group: KVM_ARM_VCPU_PMU_V3_CTRL,
    ///     attr: u64::from(KVM_ARM_VCPU_PMU_V3_INIT),
    ///     addr: 0x0,
    ///     flags: 0,
    /// };
    ///
    /// if (vcpu.has_device_attr(&dist_attr).is_ok()) {
    ///     vcpu.set_device_attr(&dist_attr).unwrap();
    /// }
    /// ```
    #[cfg(target_arch = "aarch64")]
    pub fn set_device_attr(&self, device_attr: &kvm_device_attr) -> Result<()> {
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_DEVICE_ATTR(), device_attr) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// Tests whether a cpu supports a particular attribute.
    ///
    /// See the documentation for `KVM_HAS_DEVICE_ATTR` in
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt)
    /// # Arguments
    ///
    /// * `device_attr` - The cpu attribute to be tested. `addr` field is ignored.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_ioctls::Kvm;
    /// # use kvm_bindings::{
    ///    KVM_ARM_VCPU_PMU_V3_CTRL, KVM_ARM_VCPU_PMU_V3_INIT
    /// };
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    ///
    /// let dist_attr = kvm_bindings::kvm_device_attr {
    ///     group: KVM_ARM_VCPU_PMU_V3_CTRL,
    ///     attr: u64::from(KVM_ARM_VCPU_PMU_V3_INIT),
    ///     addr: 0x0,
    ///     flags: 0,
    /// };
    ///
    /// vcpu.has_device_attr(&dist_attr);
    /// ```
    #[cfg(target_arch = "aarch64")]
    pub fn has_device_attr(&self, device_attr: &kvm_device_attr) -> Result<()> {
        let ret = unsafe { ioctl_with_ref(self, KVM_HAS_DEVICE_ATTR(), device_attr) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// Sets the vCPU general purpose registers using the `KVM_SET_REGS` ioctl.
    ///
    /// # Arguments
    ///
    /// * `regs` - general purpose registers. For details check the `kvm_regs` structure in the
    ///             [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    ///
    /// #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    /// {
    ///     // Get the current vCPU registers.
    ///     let mut regs = vcpu.get_regs().unwrap();
    ///     // Set a new value for the Instruction Pointer.
    ///     regs.rip = 0x100;
    ///     vcpu.set_regs(&regs).unwrap();
    /// }
    /// ```
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn set_regs(&self, regs: &kvm_regs) -> Result<()> {
        // Safe because we know that our file is a vCPU fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_REGS(), regs) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// Returns the vCPU special registers.
    ///
    /// The registers are returned in a `kvm_sregs` structure as defined in the
    /// [KVM API documentation](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    /// See documentation for `KVM_GET_SREGS`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    /// let sregs = vcpu.get_sregs().unwrap();
    /// ```
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_sregs(&self) -> Result<kvm_sregs> {
        // Safe because we know that our file is a vCPU fd, we know the kernel will only write the
        // correct amount of memory to our pointer, and we verify the return result.
        let mut regs = kvm_sregs::default();

        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_SREGS(), &mut regs) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(regs)
    }

    /// Sets the vCPU special registers using the `KVM_SET_SREGS` ioctl.
    ///
    /// # Arguments
    ///
    /// * `sregs` - Special registers. For details check the `kvm_sregs` structure in the
    ///             [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    /// {
    ///     let mut sregs = vcpu.get_sregs().unwrap();
    ///     // Update the code segment (cs).
    ///     sregs.cs.base = 0;
    ///     sregs.cs.selector = 0;
    ///     vcpu.set_sregs(&sregs).unwrap();
    /// }
    /// ```
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_sregs(&self, sregs: &kvm_sregs) -> Result<()> {
        // Safe because we know that our file is a vCPU fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_SREGS(), sregs) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// Returns the floating point state (FPU) from the vCPU.
    ///
    /// The state is returned in a `kvm_fpu` structure as defined in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    /// See the documentation for `KVM_GET_FPU`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    /// let fpu = vcpu.get_fpu().unwrap();
    /// ```
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_fpu(&self) -> Result<kvm_fpu> {
        let mut fpu = kvm_fpu::default();

        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_fpu struct.
            ioctl_with_mut_ref(self, KVM_GET_FPU(), &mut fpu)
        };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(fpu)
    }

    /// Set the floating point state (FPU) of a vCPU using the `KVM_SET_FPU` ioct.
    ///
    /// # Arguments
    ///
    /// * `fpu` - FPU configuration. For details check the `kvm_fpu` structure in the
    ///           [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_ioctls::Kvm;
    /// # use kvm_bindings::kvm_fpu;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    /// {
    ///     let KVM_FPU_CWD: u16 = 0x37f;
    ///     let fpu = kvm_fpu {
    ///         fcw: KVM_FPU_CWD,
    ///         ..Default::default()
    ///     };
    ///     vcpu.set_fpu(&fpu).unwrap();
    /// }
    /// ```
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_fpu(&self, fpu: &kvm_fpu) -> Result<()> {
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_fpu struct.
            ioctl_with_ref(self, KVM_SET_FPU(), fpu)
        };
        if ret < 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// X86 specific call to setup the CPUID registers.
    ///
    /// See the documentation for `KVM_SET_CPUID2`.
    ///
    /// # Arguments
    ///
    /// * `cpuid` - CPUID registers.
    ///
    /// # Example
    ///
    ///  ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let mut kvm_cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES).unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    ///
    /// // Update the CPUID entries to disable the EPB feature.
    /// const ECX_EPB_SHIFT: u32 = 3;
    /// {
    ///     let entries = kvm_cpuid.as_mut_slice();
    ///     for entry in entries.iter_mut() {
    ///         match entry.function {
    ///             6 => entry.ecx &= !(1 << ECX_EPB_SHIFT),
    ///             _ => (),
    ///         }
    ///     }
    /// }
    ///
    /// vcpu.set_cpuid2(&kvm_cpuid).unwrap();
    /// ```
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_cpuid2(&self, cpuid: &CpuId) -> Result<()> {
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_cpuid2 struct.
            ioctl_with_ptr(self, KVM_SET_CPUID2(), cpuid.as_fam_struct_ptr())
        };
        if ret < 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// X86 specific call to retrieve the CPUID registers.
    ///
    /// It requires knowledge of how many `kvm_cpuid_entry2` entries there are to get.
    /// See the documentation for `KVM_GET_CPUID2` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `num_entries` - Number of CPUID entries to be read.
    ///
    /// # Example
    ///
    ///  ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let cpuid = vcpu.get_cpuid2(KVM_MAX_CPUID_ENTRIES).unwrap();
    /// ```
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_cpuid2(&self, num_entries: usize) -> Result<CpuId> {
        if num_entries > KVM_MAX_CPUID_ENTRIES {
            // Returns the same error the underlying `ioctl` would have sent.
            return Err(errno::Error::new(libc::ENOMEM));
        }

        let mut cpuid = CpuId::new(num_entries).map_err(|_| errno::Error::new(libc::ENOMEM))?;
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_cpuid2 struct.
            ioctl_with_mut_ptr(self, KVM_GET_CPUID2(), cpuid.as_mut_fam_struct_ptr())
        };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(cpuid)
    }

    ///
    /// See the documentation for `KVM_ENABLE_CAP`.
    ///
    /// # Arguments
    ///
    /// * kvm_enable_cap - KVM capability structure. For details check the `kvm_enable_cap`
    ///                    structure in the
    ///                    [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    ///
    ///  ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_bindings::{kvm_enable_cap, KVM_MAX_CPUID_ENTRIES, KVM_CAP_HYPERV_SYNIC, KVM_CAP_SPLIT_IRQCHIP};
    /// # use kvm_ioctls::{Kvm, Cap};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let mut cap: kvm_enable_cap = Default::default();
    /// if cfg!(target_arch = "x86") || cfg!(target_arch = "x86_64") {
    ///     // KVM_CAP_HYPERV_SYNIC needs KVM_CAP_SPLIT_IRQCHIP enabled
    ///     cap.cap = KVM_CAP_SPLIT_IRQCHIP;
    ///     cap.args[0] = 24;
    ///     vm.enable_cap(&cap).unwrap();
    ///
    ///     let vcpu = vm.create_vcpu(0).unwrap();
    ///     if kvm.check_extension(Cap::HypervSynic) {
    ///         let mut cap: kvm_enable_cap = Default::default();
    ///         cap.cap = KVM_CAP_HYPERV_SYNIC;
    ///         vcpu.enable_cap(&cap).unwrap();
    ///     }
    /// }
    /// ```
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn enable_cap(&self, cap: &kvm_enable_cap) -> Result<()> {
        // The ioctl is safe because we allocated the struct and we know the
        // kernel will write exactly the size of the struct.
        let ret = unsafe { ioctl_with_ref(self, KVM_ENABLE_CAP(), cap) };
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last())
        }
    }

    /// Returns the state of the LAPIC (Local Advanced Programmable Interrupt Controller).
    ///
    /// The state is returned in a `kvm_lapic_state` structure as defined in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    /// See the documentation for `KVM_GET_LAPIC`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// // For `get_lapic` to work, you first need to create a IRQ chip before creating the vCPU.
    /// vm.create_irq_chip().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let lapic = vcpu.get_lapic().unwrap();
    /// ```
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_lapic(&self) -> Result<kvm_lapic_state> {
        let mut klapic = kvm_lapic_state::default();

        let ret = unsafe {
            // The ioctl is unsafe unless you trust the kernel not to write past the end of the
            // local_apic struct.
            ioctl_with_mut_ref(self, KVM_GET_LAPIC(), &mut klapic)
        };
        if ret < 0 {
            return Err(errno::Error::last());
        }
        Ok(klapic)
    }

    /// Sets the state of the LAPIC (Local Advanced Programmable Interrupt Controller).
    ///
    /// See the documentation for `KVM_SET_LAPIC`.
    ///
    /// # Arguments
    ///
    /// * `klapic` - LAPIC state. For details check the `kvm_lapic_state` structure in the
    ///             [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// use std::io::Write;
    ///
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// // For `get_lapic` to work, you first need to create a IRQ chip before creating the vCPU.
    /// vm.create_irq_chip().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let mut lapic = vcpu.get_lapic().unwrap();
    ///
    /// // Write to APIC_ICR offset the value 2.
    /// let apic_icr_offset = 0x300;
    /// let write_value: &[u8] = &[2, 0, 0, 0];
    /// let mut apic_icr_slice =
    ///     unsafe { &mut *(&mut lapic.regs[apic_icr_offset..] as *mut [i8] as *mut [u8]) };
    /// apic_icr_slice.write(write_value).unwrap();
    ///
    /// // Update the value of LAPIC.
    /// vcpu.set_lapic(&lapic).unwrap();
    /// ```
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_lapic(&self, klapic: &kvm_lapic_state) -> Result<()> {
        let ret = unsafe {
            // The ioctl is safe because the kernel will only read from the klapic struct.
            ioctl_with_ref(self, KVM_SET_LAPIC(), klapic)
        };
        if ret < 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// Returns the model-specific registers (MSR) for this vCPU.
    ///
    /// It emulates `KVM_GET_MSRS` ioctl's behavior by returning the number of MSRs
    /// successfully read upon success or the last error number in case of failure.
    /// The MSRs are returned in the `msr` method argument.
    ///
    /// # Arguments
    ///
    /// * `msrs`  - MSRs (input/output). For details check the `kvm_msrs` structure in the
    ///             [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_ioctls::Kvm;
    /// # use kvm_bindings::{kvm_msr_entry, Msrs};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// // Configure the struct to say which entries we want to get.
    /// let mut msrs = Msrs::from_entries(&[
    ///     kvm_msr_entry {
    ///         index: 0x0000_0174,
    ///         ..Default::default()
    ///     },
    ///     kvm_msr_entry {
    ///         index: 0x0000_0175,
    ///         ..Default::default()
    ///     },
    /// ])
    /// .unwrap();
    /// let read = vcpu.get_msrs(&mut msrs).unwrap();
    /// assert_eq!(read, 2);
    /// ```
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_msrs(&self, msrs: &mut Msrs) -> Result<usize> {
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_msrs struct.
            ioctl_with_mut_ptr(self, KVM_GET_MSRS(), msrs.as_mut_fam_struct_ptr())
        };
        if ret < 0 {
            return Err(errno::Error::last());
        }
        Ok(ret as usize)
    }

    /// Setup the model-specific registers (MSR) for this vCPU.
    /// Returns the number of MSR entries actually written.
    ///
    /// See the documentation for `KVM_SET_MSRS`.
    ///
    /// # Arguments
    ///
    /// * `msrs` - MSRs. For details check the `kvm_msrs` structure in the
    ///            [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_ioctls::Kvm;
    /// # use kvm_bindings::{kvm_msr_entry, Msrs};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    ///
    /// // Configure the entries we want to set.
    /// let mut msrs = Msrs::from_entries(&[kvm_msr_entry {
    ///     index: 0x0000_0174,
    ///     ..Default::default()
    /// }])
    /// .unwrap();
    /// let written = vcpu.set_msrs(&msrs).unwrap();
    /// assert_eq!(written, 1);
    /// ```
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_msrs(&self, msrs: &Msrs) -> Result<usize> {
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_msrs struct.
            ioctl_with_ptr(self, KVM_SET_MSRS(), msrs.as_fam_struct_ptr())
        };
        // KVM_SET_MSRS actually returns the number of msr entries written.
        if ret < 0 {
            return Err(errno::Error::last());
        }
        Ok(ret as usize)
    }

    /// Returns the vcpu's current "multiprocessing state".
    ///
    /// See the documentation for `KVM_GET_MP_STATE` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `kvm_mp_state` - multiprocessing state to be read.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let mp_state = vcpu.get_mp_state().unwrap();
    /// ```
    #[cfg(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "s390"
    ))]
    pub fn get_mp_state(&self) -> Result<kvm_mp_state> {
        let mut mp_state = Default::default();
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_mp_state struct.
            ioctl_with_mut_ref(self, KVM_GET_MP_STATE(), &mut mp_state)
        };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(mp_state)
    }

    /// Sets the vcpu's current "multiprocessing state".
    ///
    /// See the documentation for `KVM_SET_MP_STATE` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `kvm_mp_state` - multiprocessing state to be written.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let mp_state = Default::default();
    /// // Your `mp_state` manipulation here.
    /// vcpu.set_mp_state(mp_state).unwrap();
    /// ```
    #[cfg(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "s390"
    ))]
    pub fn set_mp_state(&self, mp_state: kvm_mp_state) -> Result<()> {
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_mp_state struct.
            ioctl_with_ref(self, KVM_SET_MP_STATE(), &mp_state)
        };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// X86 specific call that returns the vcpu's current "xsave struct".
    ///
    /// See the documentation for `KVM_GET_XSAVE` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `kvm_xsave` - xsave struct to be read.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let xsave = vcpu.get_xsave().unwrap();
    /// ```
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_xsave(&self) -> Result<kvm_xsave> {
        let mut xsave = Default::default();
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_xsave struct.
            ioctl_with_mut_ref(self, KVM_GET_XSAVE(), &mut xsave)
        };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(xsave)
    }

    /// X86 specific call that sets the vcpu's current "xsave struct".
    ///
    /// See the documentation for `KVM_SET_XSAVE` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `kvm_xsave` - xsave struct to be written.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let xsave = Default::default();
    /// // Your `xsave` manipulation here.
    /// vcpu.set_xsave(&xsave).unwrap();
    /// ```
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_xsave(&self, xsave: &kvm_xsave) -> Result<()> {
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_xsave struct.
            ioctl_with_ref(self, KVM_SET_XSAVE(), xsave)
        };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// X86 specific call that returns the vcpu's current "xcrs".
    ///
    /// See the documentation for `KVM_GET_XCRS` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `kvm_xcrs` - xcrs to be read.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let xcrs = vcpu.get_xcrs().unwrap();
    /// ```
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_xcrs(&self) -> Result<kvm_xcrs> {
        let mut xcrs = Default::default();
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_xcrs struct.
            ioctl_with_mut_ref(self, KVM_GET_XCRS(), &mut xcrs)
        };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(xcrs)
    }

    /// X86 specific call that sets the vcpu's current "xcrs".
    ///
    /// See the documentation for `KVM_SET_XCRS` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `kvm_xcrs` - xcrs to be written.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let xcrs = Default::default();
    /// // Your `xcrs` manipulation here.
    /// vcpu.set_xcrs(&xcrs).unwrap();
    /// ```
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_xcrs(&self, xcrs: &kvm_xcrs) -> Result<()> {
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_xcrs struct.
            ioctl_with_ref(self, KVM_SET_XCRS(), xcrs)
        };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// X86 specific call that returns the vcpu's current "debug registers".
    ///
    /// See the documentation for `KVM_GET_DEBUGREGS` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `kvm_debugregs` - debug registers to be read.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let debug_regs = vcpu.get_debug_regs().unwrap();
    /// ```
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_debug_regs(&self) -> Result<kvm_debugregs> {
        let mut debug_regs = Default::default();
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_debugregs struct.
            ioctl_with_mut_ref(self, KVM_GET_DEBUGREGS(), &mut debug_regs)
        };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(debug_regs)
    }

    /// X86 specific call that sets the vcpu's current "debug registers".
    ///
    /// See the documentation for `KVM_SET_DEBUGREGS` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `kvm_debugregs` - debug registers to be written.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let debug_regs = Default::default();
    /// // Your `debug_regs` manipulation here.
    /// vcpu.set_debug_regs(&debug_regs).unwrap();
    /// ```
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_debug_regs(&self, debug_regs: &kvm_debugregs) -> Result<()> {
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_debugregs struct.
            ioctl_with_ref(self, KVM_SET_DEBUGREGS(), debug_regs)
        };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// Returns currently pending exceptions, interrupts, and NMIs as well as related
    /// states of the vcpu.
    ///
    /// See the documentation for `KVM_GET_VCPU_EVENTS` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `kvm_vcpu_events` - vcpu events to be read.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::{Kvm, Cap};
    /// let kvm = Kvm::new().unwrap();
    /// if kvm.check_extension(Cap::VcpuEvents) {
    ///     let vm = kvm.create_vm().unwrap();
    ///     let vcpu = vm.create_vcpu(0).unwrap();
    ///     let vcpu_events = vcpu.get_vcpu_events().unwrap();
    /// }
    /// ```
    #[cfg(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64"
    ))]
    pub fn get_vcpu_events(&self) -> Result<kvm_vcpu_events> {
        let mut vcpu_events = Default::default();
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_vcpu_events struct.
            ioctl_with_mut_ref(self, KVM_GET_VCPU_EVENTS(), &mut vcpu_events)
        };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(vcpu_events)
    }

    /// Sets pending exceptions, interrupts, and NMIs as well as related states of the vcpu.
    ///
    /// See the documentation for `KVM_SET_VCPU_EVENTS` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `kvm_vcpu_events` - vcpu events to be written.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::{Kvm, Cap};
    /// let kvm = Kvm::new().unwrap();
    /// if kvm.check_extension(Cap::VcpuEvents) {
    ///     let vm = kvm.create_vm().unwrap();
    ///     let vcpu = vm.create_vcpu(0).unwrap();
    ///     let vcpu_events = Default::default();
    ///     // Your `vcpu_events` manipulation here.
    ///     vcpu.set_vcpu_events(&vcpu_events).unwrap();
    /// }
    /// ```
    #[cfg(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64"
    ))]

    pub fn set_vcpu_events(&self, vcpu_events: &kvm_vcpu_events) -> Result<()> {
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_vcpu_events struct.
            ioctl_with_ref(self, KVM_SET_VCPU_EVENTS(), vcpu_events)
        };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// Sets the type of CPU to be exposed to the guest and optional features.
    ///
    /// This initializes an ARM vCPU to the specified type with the specified features
    /// and resets the values of all of its registers to defaults. See the documentation for
    /// `KVM_ARM_VCPU_INIT`.
    ///
    /// # Arguments
    ///
    /// * `kvi` - information about preferred CPU target type and recommended features for it.
    ///           For details check the `kvm_vcpu_init` structure in the
    ///           [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_ioctls::Kvm;
    /// use kvm_bindings::kvm_vcpu_init;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    ///
    /// let mut kvi = kvm_vcpu_init::default();
    /// vm.get_preferred_target(&mut kvi).unwrap();
    /// vcpu.vcpu_init(&kvi).unwrap();
    /// ```
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    pub fn vcpu_init(&self, kvi: &kvm_vcpu_init) -> Result<()> {
        // This is safe because we allocated the struct and we know the kernel will read
        // exactly the size of the struct.
        let ret = unsafe { ioctl_with_ref(self, KVM_ARM_VCPU_INIT(), kvi) };
        if ret < 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// Returns the guest registers that are supported for the
    /// KVM_GET_ONE_REG/KVM_SET_ONE_REG calls.
    ///
    /// # Arguments
    ///
    /// * `reg_list`  - list of registers (input/output). For details check the `kvm_reg_list`
    ///                 structure in the
    ///                 [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_ioctls::Kvm;
    /// # use kvm_bindings::RegList;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    ///
    /// // KVM_GET_REG_LIST demands that the vcpus be initalized.
    /// let mut kvi: kvm_bindings::kvm_vcpu_init = kvm_bindings::kvm_vcpu_init::default();
    /// vm.get_preferred_target(&mut kvi).unwrap();
    /// vcpu.vcpu_init(&kvi).expect("Cannot initialize vcpu");
    ///
    /// let mut reg_list = RegList::new(500).unwrap();
    /// vcpu.get_reg_list(&mut reg_list).unwrap();
    /// assert!(reg_list.as_fam_struct_ref().n > 0);
    /// ```
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    pub fn get_reg_list(&self, reg_list: &mut RegList) -> Result<()> {
        let ret =
            unsafe { ioctl_with_mut_ref(self, KVM_GET_REG_LIST(), reg_list.as_mut_fam_struct()) };
        if ret < 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// Sets processor-specific debug registers and configures the vcpu for handling
    /// certain guest debug events using the `KVM_SET_GUEST_DEBUG` ioctl.
    ///
    /// # Arguments
    ///
    /// * `debug_struct` - control bitfields and debug registers, depending on the specific architecture.
    ///             For details check the `kvm_guest_debug` structure in the
    ///             [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_ioctls::Kvm;
    /// # use kvm_bindings::{
    /// #     KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_USE_SW_BP, kvm_guest_debug_arch, kvm_guest_debug
    /// # };
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    ///
    /// #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
    /// {
    ///     let debug_struct = kvm_guest_debug {
    ///         // Configure the vcpu so that a KVM_DEBUG_EXIT would be generated
    ///         // when encountering a software breakpoint during execution
    ///         control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP,
    ///         pad: 0,
    ///         // Reset all arch-specific debug registers
    ///         arch: Default::default(),
    ///     };
    ///
    ///     vcpu.set_guest_debug(&debug_struct).unwrap();
    /// }
    /// ```
    #[cfg(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "s390",
        target_arch = "ppc"
    ))]
    pub fn set_guest_debug(&self, debug_struct: &kvm_guest_debug) -> Result<()> {
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_GUEST_DEBUG(), debug_struct) };
        if ret < 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// Sets the value of one register for this vCPU.
    ///
    /// The id of the register is encoded as specified in the kernel documentation
    /// for `KVM_SET_ONE_REG`.
    ///
    /// # Arguments
    ///
    /// * `reg_id` - ID of the register for which we are setting the value.
    /// * `data` - value for the specified register.
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    pub fn set_one_reg(&self, reg_id: u64, data: u128) -> Result<()> {
        let data_ptr = &data as *const _;
        let onereg = kvm_one_reg {
            id: reg_id,
            addr: data_ptr as u64,
        };
        // This is safe because we allocated the struct and we know the kernel will read
        // exactly the size of the struct.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_ONE_REG(), &onereg) };
        if ret < 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// Returns the value of the specified vCPU register.
    ///
    /// The id of the register is encoded as specified in the kernel documentation
    /// for `KVM_GET_ONE_REG`.
    ///
    /// # Arguments
    ///
    /// * `reg_id` - ID of the register.
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    pub fn get_one_reg(&self, reg_id: u64) -> Result<u128> {
        let mut reg_value = 0;
        let mut onereg = kvm_one_reg {
            id: reg_id,
            addr: &mut reg_value as *mut _ as u64,
        };

        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_ONE_REG(), &mut onereg) };
        if ret < 0 {
            return Err(errno::Error::last());
        }
        Ok(reg_value)
    }

    /// Notify the guest about the vCPU being paused.
    ///
    /// See the documentation for `KVM_KVMCLOCK_CTRL` in the
    /// [KVM API documentation](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn kvmclock_ctrl(&self) -> Result<()> {
        // Safe because we know that our file is a KVM fd and that the request
        // is one of the ones defined by kernel.
        let ret = unsafe { ioctl(self, KVM_KVMCLOCK_CTRL()) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// Triggers the running of the current virtual CPU returning an exit reason.
    ///
    /// See documentation for `KVM_RUN`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use std::io::Write;
    /// # use std::ptr::null_mut;
    /// # use std::slice;
    /// # use kvm_ioctls::{Kvm, VcpuExit};
    /// # use kvm_bindings::{kvm_userspace_memory_region, KVM_MEM_LOG_DIRTY_PAGES};
    /// # let kvm = Kvm::new().unwrap();
    /// # let vm = kvm.create_vm().unwrap();
    /// // This is a dummy example for running on x86 based on https://lwn.net/Articles/658511/.
    /// #[cfg(target_arch = "x86_64")]
    /// {
    ///     let mem_size = 0x4000;
    ///     let guest_addr: u64 = 0x1000;
    ///     let load_addr: *mut u8 = unsafe {
    ///         libc::mmap(
    ///             null_mut(),
    ///             mem_size,
    ///             libc::PROT_READ | libc::PROT_WRITE,
    ///             libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
    ///             -1,
    ///             0,
    ///         ) as *mut u8
    ///     };
    ///
    ///     let mem_region = kvm_userspace_memory_region {
    ///         slot: 0,
    ///         guest_phys_addr: guest_addr,
    ///         memory_size: mem_size as u64,
    ///         userspace_addr: load_addr as u64,
    ///         flags: 0,
    ///     };
    ///     unsafe { vm.set_user_memory_region(mem_region).unwrap() };
    ///
    ///     // Dummy x86 code that just calls halt.
    ///     let x86_code = [0xf4 /* hlt */];
    ///
    ///     // Write the code in the guest memory. This will generate a dirty page.
    ///     unsafe {
    ///         let mut slice = slice::from_raw_parts_mut(load_addr, mem_size);
    ///         slice.write(&x86_code).unwrap();
    ///     }
    ///
    ///     let vcpu_fd = vm.create_vcpu(0).unwrap();
    ///
    ///     let mut vcpu_sregs = vcpu_fd.get_sregs().unwrap();
    ///     vcpu_sregs.cs.base = 0;
    ///     vcpu_sregs.cs.selector = 0;
    ///     vcpu_fd.set_sregs(&vcpu_sregs).unwrap();
    ///
    ///     let mut vcpu_regs = vcpu_fd.get_regs().unwrap();
    ///     // Set the Instruction Pointer to the guest address where we loaded the code.
    ///     vcpu_regs.rip = guest_addr;
    ///     vcpu_regs.rax = 2;
    ///     vcpu_regs.rbx = 3;
    ///     vcpu_regs.rflags = 2;
    ///     vcpu_fd.set_regs(&vcpu_regs).unwrap();
    ///
    ///     loop {
    ///         match vcpu_fd.run().expect("run failed") {
    ///             VcpuExit::Hlt => {
    ///                 break;
    ///             }
    ///             exit_reason => panic!("unexpected exit reason: {:?}", exit_reason),
    ///         }
    ///     }
    /// }
    /// ```
    pub fn run(&self) -> Result<VcpuExit> {
        // Safe because we know that our file is a vCPU fd and we verify the return result.
        let ret = unsafe { ioctl(self, KVM_RUN()) };
        if ret == 0 {
            let run = self.kvm_run_ptr.as_mut_ref();
            match run.exit_reason {
                // make sure you treat all possible exit reasons from include/uapi/linux/kvm.h corresponding
                // when upgrading to a different kernel version
                KVM_EXIT_UNKNOWN => Ok(VcpuExit::Unknown),
                KVM_EXIT_EXCEPTION => Ok(VcpuExit::Exception),
                KVM_EXIT_IO => {
                    let run_start = run as *mut kvm_run as *mut u8;
                    // Safe because the exit_reason (which comes from the kernel) told us which
                    // union field to use.
                    let io = unsafe { run.__bindgen_anon_1.io };
                    let port = io.port;
                    let data_size = io.count as usize * io.size as usize;
                    // The data_offset is defined by the kernel to be some number of bytes into the
                    // kvm_run stucture, which we have fully mmap'd.
                    let data_ptr = unsafe { run_start.offset(io.data_offset as isize) };
                    // The slice's lifetime is limited to the lifetime of this vCPU, which is equal
                    // to the mmap of the `kvm_run` struct that this is slicing from.
                    let data_slice = unsafe {
                        std::slice::from_raw_parts_mut::<u8>(data_ptr as *mut u8, data_size)
                    };
                    match u32::from(io.direction) {
                        KVM_EXIT_IO_IN => Ok(VcpuExit::IoIn(port, data_slice)),
                        KVM_EXIT_IO_OUT => Ok(VcpuExit::IoOut(port, data_slice)),
                        _ => Err(errno::Error::new(EINVAL)),
                    }
                }
                KVM_EXIT_HYPERCALL => {
                    // SAFETY: Safe because the exit_reason (which comes from the kernel) told us
                    // which union field to use.
                    let hypercall = unsafe { &mut run.__bindgen_anon_1.hypercall };
                    Ok(VcpuExit::Hypercall(HypercallExit {
                        nr: hypercall.nr,
                        args: hypercall.args,
                        ret: &mut hypercall.ret,
                        longmode: hypercall.longmode,
                    }))
                },
                KVM_EXIT_DEBUG => {
                    // Safe because the exit_reason (which comes from the kernel) told us which
                    // union field to use.
                    let debug = unsafe { run.__bindgen_anon_1.debug };
                    Ok(VcpuExit::Debug(debug.arch))
                }
                KVM_EXIT_HLT => Ok(VcpuExit::Hlt),
                KVM_EXIT_MMIO => {
                    // Safe because the exit_reason (which comes from the kernel) told us which
                    // union field to use.
                    let mmio = unsafe { &mut run.__bindgen_anon_1.mmio };
                    let addr = mmio.phys_addr;
                    let len = mmio.len as usize;
                    let data_slice = &mut mmio.data[..len];
                    if mmio.is_write != 0 {
                        Ok(VcpuExit::MmioWrite(addr, data_slice))
                    } else {
                        Ok(VcpuExit::MmioRead(addr, data_slice))
                    }
                }
                KVM_EXIT_IRQ_WINDOW_OPEN => Ok(VcpuExit::IrqWindowOpen),
                KVM_EXIT_SHUTDOWN => Ok(VcpuExit::Shutdown),
                KVM_EXIT_FAIL_ENTRY => {
                    // Safe because the exit_reason (which comes from the kernel) told us which
                    // union field to use.
                    let fail_entry = unsafe { &mut run.__bindgen_anon_1.fail_entry };
                    Ok(VcpuExit::FailEntry(
                        fail_entry.hardware_entry_failure_reason,
                        fail_entry.cpu,
                    ))
                }
                KVM_EXIT_INTR => Ok(VcpuExit::Intr),
                KVM_EXIT_SET_TPR => Ok(VcpuExit::SetTpr),
                KVM_EXIT_TPR_ACCESS => Ok(VcpuExit::TprAccess),
                KVM_EXIT_S390_SIEIC => Ok(VcpuExit::S390Sieic),
                KVM_EXIT_S390_RESET => Ok(VcpuExit::S390Reset),
                KVM_EXIT_DCR => Ok(VcpuExit::Dcr),
                KVM_EXIT_NMI => Ok(VcpuExit::Nmi),
                KVM_EXIT_INTERNAL_ERROR => Ok(VcpuExit::InternalError),
                KVM_EXIT_OSI => Ok(VcpuExit::Osi),
                KVM_EXIT_PAPR_HCALL => Ok(VcpuExit::PaprHcall),
                KVM_EXIT_S390_UCONTROL => Ok(VcpuExit::S390Ucontrol),
                KVM_EXIT_WATCHDOG => Ok(VcpuExit::Watchdog),
                KVM_EXIT_S390_TSCH => Ok(VcpuExit::S390Tsch),
                KVM_EXIT_EPR => Ok(VcpuExit::Epr),
                KVM_EXIT_SYSTEM_EVENT => {
                    // Safe because the exit_reason (which comes from the kernel) told us which
                    // union field to use.
                    let system_event = unsafe { &mut run.__bindgen_anon_1.system_event };
                    Ok(VcpuExit::SystemEvent(
                        system_event.type_,
                        system_event.flags,
                    ))
                }
                KVM_EXIT_S390_STSI => Ok(VcpuExit::S390Stsi),
                KVM_EXIT_IOAPIC_EOI => {
                    // Safe because the exit_reason (which comes from the kernel) told us which
                    // union field to use.
                    let eoi = unsafe { &mut run.__bindgen_anon_1.eoi };
                    Ok(VcpuExit::IoapicEoi(eoi.vector))
                }
                KVM_EXIT_HYPERV => Ok(VcpuExit::Hyperv),
                r => Ok(VcpuExit::Unsupported(r)),
            }
        } else {
            Err(errno::Error::last())
        }
    }

    /// Returns a mutable reference to the kvm_run structure
    pub fn get_kvm_run(&mut self) -> &mut kvm_run {
        self.kvm_run_ptr.as_mut_ref()
    }

    /// Sets the `immediate_exit` flag on the `kvm_run` struct associated with this vCPU to `val`.
    pub fn set_kvm_immediate_exit(&self, val: u8) {
        let kvm_run = self.kvm_run_ptr.as_mut_ref();
        kvm_run.immediate_exit = val;
    }

    /// Returns the vCPU TSC frequency in KHz or an error if the host has unstable TSC.
    ///
    /// # Example
    ///
    ///  ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let tsc_khz = vcpu.get_tsc_khz().unwrap();
    /// ```
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_tsc_khz(&self) -> Result<u32> {
        // Safe because we know that our file is a KVM fd and that the request is one of the ones
        // defined by kernel.
        let ret = unsafe { ioctl(self, KVM_GET_TSC_KHZ()) };
        if ret >= 0 {
            Ok(ret as u32)
        } else {
            Err(errno::Error::new(ret))
        }
    }

    /// Sets the specified vCPU TSC frequency.
    ///
    /// # Arguments
    ///
    /// * `freq` - The frequency unit is KHz as per the KVM API documentation
    /// for `KVM_SET_TSC_KHZ`.
    ///
    /// # Example
    ///
    ///  ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::{Cap, Kvm};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// if kvm.check_extension(Cap::GetTscKhz) && kvm.check_extension(Cap::TscControl) {
    ///     vcpu.set_tsc_khz(1000).unwrap();
    /// }
    /// ```
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_tsc_khz(&self, freq: u32) -> Result<()> {
        // Safe because we know that our file is a KVM fd and that the request is one of the ones
        // defined by kernel.
        let ret = unsafe { ioctl_with_val(self, KVM_SET_TSC_KHZ(), freq as u64) };
        if ret < 0 {
            Err(errno::Error::last())
        } else {
            Ok(())
        }
    }

    /// Translates a virtual address according to the vCPU's current address translation mode.
    ///
    /// The physical address is returned in a `kvm_translation` structure as defined in the
    /// [KVM API documentation](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    /// See documentation for `KVM_TRANSLATE`.
    ///
    /// # Arguments
    ///
    /// * `gva` - The virtual address to translate.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    /// let tr = vcpu.translate_gva(0x10000).unwrap();
    /// ```
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn translate_gva(&self, gva: u64) -> Result<kvm_translation> {
        let mut tr = kvm_translation {
            linear_address: gva,
            ..Default::default()
        };

        // Safe because we know that our file is a vCPU fd, we know the kernel will only write the
        // correct amount of memory to our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_TRANSLATE(), &mut tr) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(tr)
    }

    /// Enable the given [`SyncReg`] to be copied to userspace on the next exit
    ///
    /// # Arguments
    ///
    /// * `reg` - The [`SyncReg`] to copy out of the guest
    ///
    /// # Example
    ///
    ///  ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::{Kvm, SyncReg, Cap};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let mut vcpu = vm.create_vcpu(0).unwrap();
    /// vcpu.set_sync_valid_reg(SyncReg::Register);
    /// vcpu.set_sync_valid_reg(SyncReg::SystemRegister);
    /// vcpu.set_sync_valid_reg(SyncReg::VcpuEvents);
    /// ```
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_sync_valid_reg(&mut self, reg: SyncReg) {
        let mut kvm_run: &mut kvm_run = self.kvm_run_ptr.as_mut_ref();
        kvm_run.kvm_valid_regs |= reg as u64;
    }

    /// Tell KVM to copy the given [`SyncReg`] into the guest on the next entry
    ///
    /// # Arguments
    ///
    /// * `reg` - The [`SyncReg`] to copy into the guest
    ///
    /// # Example
    ///
    ///  ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::{Kvm, SyncReg, Cap};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let mut vcpu = vm.create_vcpu(0).unwrap();
    /// vcpu.set_sync_dirty_reg(SyncReg::Register);
    /// ```
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_sync_dirty_reg(&mut self, reg: SyncReg) {
        let mut kvm_run: &mut kvm_run = self.kvm_run_ptr.as_mut_ref();
        kvm_run.kvm_dirty_regs |= reg as u64;
    }

    /// Disable the given [`SyncReg`] to be copied to userspace on the next exit
    ///
    /// # Arguments
    ///
    /// * `reg` - The [`SyncReg`] to not copy out of the guest
    ///
    /// # Example
    ///
    ///  ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::{Kvm, SyncReg, Cap};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let mut vcpu = vm.create_vcpu(0).unwrap();
    /// vcpu.clear_sync_valid_reg(SyncReg::Register);
    /// ```
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn clear_sync_valid_reg(&mut self, reg: SyncReg) {
        let mut kvm_run: &mut kvm_run = self.kvm_run_ptr.as_mut_ref();
        kvm_run.kvm_valid_regs &= !(reg as u64);
    }

    /// Tell KVM to not copy the given [`SyncReg`] into the guest on the next entry
    ///
    /// # Arguments
    ///
    /// * `reg` - The [`SyncReg`] to not copy out into the guest
    ///
    /// # Example
    ///
    ///  ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::{Kvm, SyncReg, Cap};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let mut vcpu = vm.create_vcpu(0).unwrap();
    /// vcpu.clear_sync_dirty_reg(SyncReg::Register);
    /// ```
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn clear_sync_dirty_reg(&mut self, reg: SyncReg) {
        let mut kvm_run: &mut kvm_run = self.kvm_run_ptr.as_mut_ref();
        kvm_run.kvm_dirty_regs &= !(reg as u64);
    }

    /// Get the [`kvm_sync_regs`] from the VM
    ///
    /// # Example
    ///
    ///  ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::{Kvm, SyncReg, Cap};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let mut vcpu = vm.create_vcpu(0).unwrap();
    /// if kvm.check_extension(Cap::SyncRegs) {
    ///     vcpu.set_sync_valid_reg(SyncReg::Register);
    ///     vcpu.run();
    ///     let guest_rax = vcpu.sync_regs().regs.rax;
    /// }
    /// ```
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn sync_regs(&self) -> kvm_sync_regs {
        let kvm_run: &mut kvm_run = self.kvm_run_ptr.as_mut_ref();

        // SAFETY: Accessing this union field could be out of bounds if the `kvm_run`
        // allocation isn't large enough. The `kvm_run` region is set using
        // `get_vcpu_map_size`, so this region is in bounds
        unsafe { kvm_run.s.regs }
    }

    /// Get a mutable reference to the [`kvm_sync_regs`] from the VM
    ///
    /// # Example
    ///
    ///  ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::{Kvm, SyncReg, Cap};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let mut vcpu = vm.create_vcpu(0).unwrap();
    /// if kvm.check_extension(Cap::SyncRegs) {
    ///     vcpu.set_sync_valid_reg(SyncReg::Register);
    ///     vcpu.run();
    ///     // Set the guest RAX to 0xdeadbeef
    ///     vcpu.sync_regs_mut().regs.rax = 0xdeadbeef;
    ///     vcpu.set_sync_dirty_reg(SyncReg::Register);
    ///     vcpu.run();
    /// }
    /// ```
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn sync_regs_mut(&mut self) -> &mut kvm_sync_regs {
        let kvm_run: &mut kvm_run = self.kvm_run_ptr.as_mut_ref();

        // SAFETY: Accessing this union field could be out of bounds if the `kvm_run`
        // allocation isn't large enough. The `kvm_run` region is set using
        // `get_vcpu_map_size`, so this region is in bounds
        unsafe { &mut kvm_run.s.regs }
    }
}

/// Helper function to create a new `VcpuFd`.
///
/// This should not be exported as a public function because the preferred way is to use
/// `create_vcpu` from `VmFd`. The function cannot be part of the `VcpuFd` implementation because
/// then it would be exported with the public `VcpuFd` interface.
pub fn new_vcpu(vcpu: File, kvm_run_ptr: KvmRunWrapper) -> VcpuFd {
    VcpuFd { vcpu, kvm_run_ptr }
}

impl AsRawFd for VcpuFd {
    fn as_raw_fd(&self) -> RawFd {
        self.vcpu.as_raw_fd()
    }
}


