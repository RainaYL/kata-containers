// Copyright (C) 2020-2022 Alibaba Cloud. All rights reserved.
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::convert::TryInto;
#[cfg(feature = "tdx")]
use std::io::{Seek, SeekFrom};
use std::ops::Deref;
use std::os::fd::AsRawFd;

use dbs_address_space::AddressSpace;
#[cfg(feature = "tdx")]
use dbs_address_space::AddressSpaceRegionType;
#[cfg(feature = "tdx")]
use dbs_boot::layout::{MMIO_LOW_START, TD_SHIM_START};
use dbs_boot::{add_e820_entry, bootparam, layout, mptable, BootParamsWrapper, InitrdConfig};
#[cfg(feature = "tdx")]
use dbs_tdx::td_shim::{PayloadImageType, PayloadInfo, TdHob, TdvfSection, TdvfSectionType};
use dbs_utils::epoll_manager::EpollManager;
use dbs_utils::time::TimestampUs;
use kvm_bindings::{kvm_irqchip, kvm_pit_config, kvm_pit_state2, KVM_PIT_SPEAKER_DUMMY};
use linux_loader::cmdline::Cmdline;
use linux_loader::configurator::{linux::LinuxBootConfigurator, BootConfigurator, BootParams};
use slog::info;
#[cfg(feature = "tdx")]
use vm_memory::Bytes;
use vm_memory::{Address, GuestAddress, GuestAddressSpace, GuestMemory};

#[cfg(feature = "tdx")]
use crate::address_space_manager::AddressManagerError;
use crate::address_space_manager::{GuestAddressSpaceImpl, GuestMemoryImpl};
#[cfg(feature = "tdx")]
use crate::error::LoadTdDataError;
use crate::error::{Error, Result, StartMicroVmError};
use crate::event_manager::EventManager;
use crate::vm::{Vm, VmError};

/// Configures the system and should be called once per vm before starting vcpu
/// threads.
///
/// # Arguments
///
/// * `guest_mem` - The memory to be used by the guest.
/// * `cmdline_addr` - Address in `guest_mem` where the kernel command line was
///   loaded.
/// * `cmdline_size` - Size of the kernel command line in bytes including the
///   null terminator.
/// * `initrd` - Information about where the ramdisk image was loaded in the
///   `guest_mem`.
/// * `boot_cpus` - Number of virtual CPUs the guest will have at boot time.
/// * `max_cpus` - Max number of virtual CPUs the guest will have.
/// * `rsv_mem_bytes` - Reserve memory from microVM..
#[allow(clippy::too_many_arguments)]
fn configure_system<M: GuestMemory>(
    guest_mem: &M,
    address_space: Option<&AddressSpace>,
    cmdline_addr: GuestAddress,
    cmdline_size: usize,
    initrd: &Option<InitrdConfig>,
    boot_cpus: u8,
    max_cpus: u8,
    pci_legacy_irqs: Option<&HashMap<u8, u8>>,
) -> super::Result<()> {
    const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
    const KERNEL_HDR_MAGIC: u32 = 0x5372_6448;
    const KERNEL_LOADER_OTHER: u8 = 0xff;
    const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x0100_0000; // Must be non-zero.

    let mmio_start = GuestAddress(layout::MMIO_LOW_START);
    let mmio_end = GuestAddress(layout::MMIO_LOW_END);
    let himem_start = GuestAddress(layout::HIMEM_START);

    // Note that this puts the mptable at the last 1k of Linux's 640k base RAM
    mptable::setup_mptable(guest_mem, boot_cpus, max_cpus, pci_legacy_irqs)
        .map_err(Error::MpTableSetup)?;

    let mut params: BootParamsWrapper = BootParamsWrapper(bootparam::boot_params::default());

    params.0.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    params.0.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
    params.0.hdr.header = KERNEL_HDR_MAGIC;
    params.0.hdr.cmd_line_ptr = cmdline_addr.raw_value() as u32;
    params.0.hdr.cmdline_size = cmdline_size as u32;
    params.0.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;
    if let Some(initrd_config) = initrd {
        params.0.hdr.ramdisk_image = initrd_config.address.raw_value() as u32;
        params.0.hdr.ramdisk_size = initrd_config.size as u32;
    }

    add_e820_entry(&mut params.0, 0, layout::EBDA_START, bootparam::E820_RAM)
        .map_err(Error::BootSystem)?;

    let mem_end = address_space.ok_or(Error::AddressSpace)?.last_addr();
    if mem_end < mmio_start {
        add_e820_entry(
            &mut params.0,
            himem_start.raw_value(),
            // it's safe to use unchecked_offset_from because
            // mem_end > himem_start
            mem_end.unchecked_offset_from(himem_start) + 1,
            bootparam::E820_RAM,
        )
        .map_err(Error::BootSystem)?;
    } else {
        add_e820_entry(
            &mut params.0,
            himem_start.raw_value(),
            // it's safe to use unchecked_offset_from because
            // end_32bit_gap_start > himem_start
            mmio_start.unchecked_offset_from(himem_start),
            bootparam::E820_RAM,
        )
        .map_err(Error::BootSystem)?;
        if mem_end > mmio_end {
            add_e820_entry(
                &mut params.0,
                mmio_end.raw_value() + 1,
                // it's safe to use unchecked_offset_from because mem_end > mmio_end
                mem_end.unchecked_offset_from(mmio_end),
                bootparam::E820_RAM,
            )
            .map_err(Error::BootSystem)?;
        }
    }

    LinuxBootConfigurator::write_bootparams(
        &BootParams::new(&params, GuestAddress(layout::ZERO_PAGE_START)),
        guest_mem,
    )
    .map_err(|_| Error::ZeroPageSetup)
}

impl Vm {
    /// Get the status of in-kernel PIT.
    pub fn get_pit_state(&self) -> Result<kvm_pit_state2> {
        self.vm_fd
            .get_pit2()
            .map_err(|e| Error::Vm(VmError::Irq(e)))
    }

    /// Set the status of in-kernel PIT.
    pub fn set_pit_state(&self, pit_state: &kvm_pit_state2) -> Result<()> {
        self.vm_fd
            .set_pit2(pit_state)
            .map_err(|e| Error::Vm(VmError::Irq(e)))
    }

    /// Get the status of in-kernel ioapic.
    pub fn get_irqchip_state(&self, chip_id: u32) -> Result<kvm_irqchip> {
        let mut irqchip: kvm_irqchip = kvm_irqchip {
            chip_id,
            ..kvm_irqchip::default()
        };
        self.vm_fd
            .get_irqchip(&mut irqchip)
            .map(|_| irqchip)
            .map_err(|e| Error::Vm(VmError::Irq(e)))
    }

    /// Set the status of in-kernel ioapic.
    pub fn set_irqchip_state(&self, irqchip: &kvm_irqchip) -> Result<()> {
        self.vm_fd
            .set_irqchip(irqchip)
            .map_err(|e| Error::Vm(VmError::Irq(e)))
    }
}

impl Vm {
    /// Initialize the virtual machine instance.
    ///
    /// It initialize the virtual machine instance by:
    /// 1) initialize virtual machine global state and configuration.
    /// 2) create system devices, such as interrupt controller, PIT etc.
    /// 3) create and start IO devices, such as serial, console, block, net, vsock etc.
    /// 4) create and initialize vCPUs.
    /// 5) configure CPU power management features.
    /// 6) load guest kernel image.
    pub fn init_microvm(
        &mut self,
        epoll_mgr: EpollManager,
        vm_as: GuestAddressSpaceImpl,
        request_ts: TimestampUs,
    ) -> std::result::Result<(), StartMicroVmError> {
        info!(self.logger, "VM: start initializing microvm ...");

        self.init_tss()?;
        // For x86_64 we need to create the interrupt controller before calling `KVM_CREATE_VCPUS`
        // while on aarch64 we need to do it the other way around.
        self.setup_interrupt_controller()?;
        self.create_pit()?;
        self.init_devices(epoll_mgr)?;

        let reset_event_fd = self.device_manager.get_reset_eventfd().unwrap();
        self.vcpu_manager()
            .map_err(StartMicroVmError::Vcpu)?
            .set_reset_event_fd(reset_event_fd)
            .map_err(StartMicroVmError::Vcpu)?;

        if self.vm_config.cpu_pm == "on" {
            // TODO: add cpu_pm support. issue #4590.
            info!(self.logger, "VM: enable CPU disable_idle_exits capability");
        }

        #[cfg(feature = "tdx")]
        if self.is_tdx_enabled() {
            return self.init_tdx_microvm(vm_as);
        }

        let vm_memory = vm_as.memory();
        let kernel_loader_result = self.load_kernel(
            vm_memory.deref(),
            #[cfg(feature = "tdx")]
            None,
        )?;
        self.vcpu_manager()
            .map_err(StartMicroVmError::Vcpu)?
            .create_boot_vcpus(request_ts, kernel_loader_result.kernel_load)
            .map_err(StartMicroVmError::Vcpu)?;

        info!(self.logger, "VM: initializing microvm done");
        Ok(())
    }

    /// Execute system architecture specific configurations.
    ///
    /// 1) set guest kernel boot parameters
    /// 2) setup BIOS configuration data structs, mainly implement the MPSpec.
    pub fn configure_system_arch(
        &self,
        vm_memory: &GuestMemoryImpl,
        cmdline: &Cmdline,
        initrd: Option<InitrdConfig>,
    ) -> std::result::Result<(), StartMicroVmError> {
        let cmdline_addr = GuestAddress(dbs_boot::layout::CMDLINE_START);
        linux_loader::loader::load_cmdline(vm_memory, cmdline_addr, cmdline)
            .map_err(StartMicroVmError::LoadCommandline)?;

        let cmdline_size = cmdline
            .as_cstring()
            .map_err(StartMicroVmError::ProcessCommandlne)?
            .as_bytes_with_nul()
            .len();

        #[cfg(feature = "host-device")]
        {
            // Don't expect poisoned lock here.
            let vfio_manager = self.device_manager.vfio_manager.lock().unwrap();
            configure_system(
                vm_memory,
                self.address_space.address_space(),
                cmdline_addr,
                cmdline_size,
                &initrd,
                self.vm_config.vcpu_count,
                self.vm_config.max_vcpu_count,
                vfio_manager.get_pci_legacy_irqs(),
            )
            .map_err(StartMicroVmError::ConfigureSystem)
        }

        #[cfg(not(feature = "host-device"))]
        configure_system(
            vm_memory,
            self.address_space.address_space(),
            cmdline_addr,
            cmdline_size,
            &initrd,
            self.vm_config.vcpu_count,
            self.vm_config.max_vcpu_count,
            None,
        )
        .map_err(StartMicroVmError::ConfigureSystem)
    }

    /// Initializes the guest memory.
    pub(crate) fn init_tss(&mut self) -> std::result::Result<(), StartMicroVmError> {
        self.vm_fd
            .set_tss_address(dbs_boot::layout::KVM_TSS_ADDRESS.try_into().unwrap())
            .map_err(|e| StartMicroVmError::ConfigureVm(VmError::VmSetup(e)))
    }

    /// Creates the irq chip and an in-kernel device model for the PIT.
    pub(crate) fn setup_interrupt_controller(
        &mut self,
    ) -> std::result::Result<(), StartMicroVmError> {
        // TDX uses split irqchip, and irqchip is created while wnabling KVM_CAP_SPLIT_IRQCHIP
        // Therefore no need to call KVM_CREATE_IRQCHIP
        #[cfg(feature = "tdx")]
        if self.is_tdx_enabled() {
            return Ok(());
        }
        self.vm_fd
            .create_irq_chip()
            .map_err(|e| StartMicroVmError::ConfigureVm(VmError::VmSetup(e)))
    }

    /// Creates an in-kernel device model for the PIT.
    pub(crate) fn create_pit(&self) -> std::result::Result<(), StartMicroVmError> {
        #[cfg(feature = "tdx")]
        if self.is_tdx_enabled() {
            return Ok(());
        }

        info!(self.logger, "VM: create pit");
        // We need to enable the emulation of a dummy speaker port stub so that writing to port 0x61
        // (i.e. KVM_SPEAKER_BASE_ADDRESS) does not trigger an exit to user space.
        let pit_config = kvm_pit_config {
            flags: KVM_PIT_SPEAKER_DUMMY,
            ..kvm_pit_config::default()
        };

        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        self.vm_fd
            .create_pit2(pit_config)
            .map_err(|e| StartMicroVmError::ConfigureVm(VmError::VmSetup(e)))
    }

    pub(crate) fn register_events(
        &mut self,
        event_mgr: &mut EventManager,
    ) -> std::result::Result<(), StartMicroVmError> {
        let reset_evt = self
            .device_manager
            .get_reset_eventfd()
            .map_err(StartMicroVmError::DeviceManager)?;
        event_mgr
            .register_exit_eventfd(&reset_evt)
            .map_err(|_| StartMicroVmError::RegisterEvent)?;
        self.reset_eventfd = Some(reset_evt);

        Ok(())
    }

    #[cfg(feature = "tdx")]
    fn init_tdx_microvm(
        &mut self,
        vm_as: GuestAddressSpaceImpl,
    ) -> std::result::Result<(), StartMicroVmError> {
        // Init tdx
        self.init_tdx()?;

        let boot_vcpu_count = self.vm_config().vcpu_count;
        self.vcpu_manager()
            .map_err(StartMicroVmError::Vcpu)?
            .create_vcpus(
                boot_vcpu_count,
                None,
                None,
                #[cfg(feature = "tdx")]
                true,
            )
            .map_err(StartMicroVmError::Vcpu)?;

        let vm_memory = vm_as.memory();
        let sections = self.parse_tdvf_sections()?;
        let (hob_offset, payload_offset, payload_size, cmdline_offset) =
            self.load_tdshim(vm_memory.deref(), &sections)?;

        let payload_info =
            self.load_tdx_payload(payload_offset, payload_size, vm_memory.deref())?;

        self.load_tdx_cmdline(cmdline_offset, vm_memory.deref())?;

        self.vcpu_manager()
            .map_err(StartMicroVmError::Vcpu)?
            .init_tdx_vcpus(hob_offset)
            .map_err(StartMicroVmError::Vcpu)?;

        let address_space =
            self.vm_address_space()
                .cloned()
                .ok_or(StartMicroVmError::GuestMemory(
                    AddressManagerError::GuestMemoryNotInitialized,
                ))?;
        self.generate_hob_list(hob_offset, vm_memory.deref(), address_space, payload_info)
            .map_err(LoadTdDataError::LoadData)
            .map_err(StartMicroVmError::TdDataLoader)?;

        for section in sections {
            let host_address = vm_memory
                .deref()
                .get_host_address(GuestAddress(section.address))
                .unwrap();
            self.init_tdx_memory(
                host_address as u64,
                section.address,
                section.size,
                section.attributes,
            )?;
        }

        self.finalize_tdx()?;

        Ok(())
    }

    #[cfg(feature = "tdx")]
    fn init_tdx(&self) -> std::result::Result<(), StartMicroVmError> {
        let tdx_caps = self.tdx_caps.as_ref().unwrap();
        let mut supported_cpuid = self.vcpu_manager().unwrap().supported_cpuid.clone();
        dbs_tdx::filter_tdx_cpuid(&tdx_caps.cpu_id, &mut supported_cpuid);
        dbs_tdx::tdx_init(
            &self.vm_fd.as_raw_fd(),
            tdx_caps.supported_attrs,
            tdx_caps.supported_xfam,
            supported_cpuid,
        )
        .map_err(StartMicroVmError::TdxError)?;

        Ok(())
    }

    #[cfg(feature = "tdx")]
    fn parse_tdvf_sections(&mut self) -> std::result::Result<Vec<TdvfSection>, StartMicroVmError> {
        let kernel_config = self
            .kernel_config
            .as_mut()
            .ok_or(StartMicroVmError::MissingKernelConfig)?;

        let tdshim_file = kernel_config.tdshim_file_mut().unwrap();

        dbs_tdx::td_shim::parse_tdvf_sections(tdshim_file)
            .map_err(LoadTdDataError::ParseTdshim)
            .map_err(StartMicroVmError::TdDataLoader)
    }

    #[cfg(feature = "tdx")]
    fn load_tdshim(
        &mut self,
        vm_memory: &GuestMemoryImpl,
        sections: &[TdvfSection],
    ) -> std::result::Result<(u64, u64, u64, u64), StartMicroVmError> {
        let mut hob_offset: Option<u64> = None;
        let mut payload_offset: Option<u64> = None;
        let mut payload_size: Option<u64> = None;
        let mut cmdline_offset: Option<u64> = None;

        let kernel_config = self
            .kernel_config
            .as_mut()
            .ok_or(StartMicroVmError::MissingKernelConfig)?;

        let tdshim_file = kernel_config.tdshim_file_mut().unwrap();

        for section in sections {
            match section.r#type {
                TdvfSectionType::Bfv | TdvfSectionType::Cfv => {
                    tdshim_file
                        .seek(SeekFrom::Start(section.data_offset as u64))
                        .map_err(LoadTdDataError::ReadTdshim)
                        .map_err(StartMicroVmError::TdDataLoader)?;
                    vm_memory
                        .read_from(
                            GuestAddress(section.address),
                            tdshim_file,
                            section.data_size as usize,
                        )
                        .map_err(LoadTdDataError::LoadData)
                        .map_err(StartMicroVmError::TdDataLoader)?;
                }
                TdvfSectionType::TdHob => {
                    hob_offset = Some(section.address);
                }
                TdvfSectionType::Payload => {
                    payload_offset = Some(section.address);
                    payload_size = Some(section.size);
                }
                TdvfSectionType::PayloadParam => {
                    cmdline_offset = Some(section.address);
                }
                _ => {}
            }
        }

        if hob_offset.is_none() {
            return Err(StartMicroVmError::TdDataLoader(LoadTdDataError::HobOffset));
        }

        if payload_offset.is_none() || payload_size.is_none() {
            return Err(StartMicroVmError::TdDataLoader(
                LoadTdDataError::PayloadOffset,
            ));
        }

        if cmdline_offset.is_none() {
            return Err(StartMicroVmError::TdDataLoader(
                LoadTdDataError::PayloadParamsOffset,
            ));
        }

        Ok((
            hob_offset.unwrap(),
            payload_offset.unwrap(),
            payload_size.unwrap(),
            cmdline_offset.unwrap(),
        ))
    }

    #[cfg(feature = "tdx")]
    fn load_tdx_payload(
        &mut self,
        payload_offset: u64,
        payload_size: u64,
        vm_memory: &GuestMemoryImpl,
    ) -> std::result::Result<PayloadInfo, StartMicroVmError> {
        let kernel_loader_result =
            self.load_kernel(vm_memory, Some(GuestAddress(payload_offset)))?;

        if kernel_loader_result.kernel_end > (payload_offset + payload_size) {
            Err(StartMicroVmError::TdDataLoader(
                LoadTdDataError::LoadPayload,
            ))
        } else {
            let payload_info = PayloadInfo {
                image_type: PayloadImageType::RawVmLinux,
                entry_point: kernel_loader_result.kernel_load.0,
            };
            Ok(payload_info)
        }
    }

    #[cfg(feature = "tdx")]
    fn load_tdx_cmdline(
        &mut self,
        cmdline_offset: u64,
        vm_memory: &GuestMemoryImpl,
    ) -> std::result::Result<(), StartMicroVmError> {
        let cmdline = self
            .kernel_config
            .as_ref()
            .ok_or(StartMicroVmError::MissingKernelConfig)?
            .kernel_cmdline();
        linux_loader::loader::load_cmdline(vm_memory, GuestAddress(cmdline_offset), cmdline)
            .map_err(StartMicroVmError::LoadCommandline)?;
        Ok(())
    }

    #[cfg(feature = "tdx")]
    fn generate_hob_list(
        &self,
        hob_offset: u64,
        vm_memory: &GuestMemoryImpl,
        address_space: AddressSpace,
        payload_info: PayloadInfo,
    ) -> std::result::Result<(), vm_memory::GuestMemoryError> {
        let mut hob = TdHob::start(hob_offset);

        let mut memory_regions: Vec<(bool, u64, u64)> = Vec::new();
        address_space
            .walk_regions(|region| {
                match region.region_type() {
                    AddressSpaceRegionType::DefaultMemory => {
                        memory_regions.push((true, region.start_addr().0, region.len()));
                    }
                    AddressSpaceRegionType::Firmware => {
                        memory_regions.push((false, region.start_addr().0, region.len()));
                    }
                    _ => {}
                }
                Ok(())
            })
            .unwrap();

        for (is_ram, start, size) in memory_regions {
            hob.add_memory_resource(vm_memory, start, size, is_ram)?;
        }

        hob.add_mmio_resource(vm_memory, MMIO_LOW_START, TD_SHIM_START - MMIO_LOW_START)?;
        hob.add_payload(vm_memory, payload_info)?;

        hob.finish(vm_memory)
    }

    #[cfg(feature = "tdx")]
    fn init_tdx_memory(
        &mut self,
        host_address: u64,
        guest_address: u64,
        size: u64,
        flags: u32,
    ) -> std::result::Result<(), StartMicroVmError> {
        let vcpus_manager = self.vcpu_manager().map_err(StartMicroVmError::Vcpu)?;
        let vcpus = vcpus_manager.vcpus();

        if vcpus.is_empty() {
            return Err(StartMicroVmError::Vcpu(
                crate::vcpu::VcpuManagerError::MissingVcpuFds,
            ));
        }

        dbs_tdx::tdx_init_mem_region(
            &vcpus[0].vcpu_fd().as_raw_fd(),
            host_address,
            guest_address,
            size / dbs_boot::PAGE_SIZE as u64,
            flags,
        )
        .map_err(StartMicroVmError::TdxError)
    }

    #[cfg(feature = "tdx")]
    fn finalize_tdx(&self) -> std::result::Result<(), StartMicroVmError> {
        dbs_tdx::tdx_finalize(&self.vm_fd().as_raw_fd()).map_err(StartMicroVmError::TdxError)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::api::v1::InstanceInfo;
    use crate::device_manager::blk_dev_mgr::BlockDeviceConfigInfo;
    use crate::vm::{BpfProgram, CpuTopology, KernelConfigInfo, VmConfigInfo};
    use std::fs::File;
    use std::path::PathBuf;
    use std::sync::{Arc, RwLock, mpsc};
    use vmm_sys_util::eventfd::EventFd;

    #[cfg(feature = "tdx")]
    fn get_vm() -> Vm {
        let instance_info = Arc::new(RwLock::new(InstanceInfo::new(
            "".to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
            true,
        )));
        let epoll_manager = EpollManager::default();
        let mut vm = Vm::new(None, instance_info, epoll_manager.clone()).unwrap();
        let vm_config = VmConfigInfo {
            vcpu_count: 1,
            max_vcpu_count: 3,
            cpu_pm: "off".to_string(),
            mem_type: "anon".to_string(),
            mem_file_path: "".to_string(),
            mem_size_mib: 1024,
            serial_path: None,
            cpu_topology: CpuTopology {
                threads_per_core: 3,
                cores_per_die: 1,
                dies_per_socket: 1,
                sockets: 1,
            },
            vpmu_feature: 0,
            pci_hotplug_enabled: false,
        };
        vm.set_vm_config(vm_config);
        vm.init_guest_memory().unwrap();

        vm.init_vcpu_manager(vm.vm_as().unwrap().clone(), BpfProgram::default())
            .unwrap();

        vm.vcpu_manager()
            .unwrap()
            .set_reset_event_fd(EventFd::new(libc::EFD_NONBLOCK).unwrap())
            .unwrap();

        vm.setup_interrupt_controller().unwrap();

        vm
    }

    #[test]
    #[cfg(feature = "tdx")]
    fn test_tdx_init() {
        let kernel_path = "/tmp/test_resources/vmlinux-confidential.container";
        let tdshim_path = "/tmp/test_resources/final.bin";

        let boot_args = "console=ttyS0 console=ttyS1 earlyprintk=ttyS1 tty0 reboot=k debug panic=1 pci=off root=/dev/vda1";
        let mut cmd_line = Cmdline::new(256).unwrap();
        cmd_line.insert_str(boot_args).unwrap();

        let mut vm = get_vm();

        vm.set_kernel_config(KernelConfigInfo::new(
            Some(File::open(tdshim_path).unwrap()),
            File::open(kernel_path).unwrap(),
            None,
            cmd_line,
        ));

        let block_device_config_info = BlockDeviceConfigInfo {
            drive_id: String::from("rootfs"),
            path_on_host: PathBuf::from("/tmp/test_resources/kata-ubuntu-noble-confidential.image"),
            is_root_device: true,
            is_read_only: false,
            ..Default::default()
        };
        let ctx = vm.create_device_op_context(Some(vm.epoll_manager().clone())).unwrap();
        let (sender, _) = mpsc::channel();
        vm.device_manager_mut().block_manager.insert_device(ctx, block_device_config_info, sender).unwrap();

        vm.init_devices(vm.epoll_manager().clone()).unwrap();

        vm.init_tdx().unwrap();

        let vm_memory = vm.vm_as().unwrap().memory();
        let sections = vm.parse_tdvf_sections().unwrap();
        let (hob_offset, payload_offset, payload_size, cmdline_offset) =
            vm.load_tdshim(vm_memory.deref(), &sections).unwrap();

        let payload_info = vm
            .load_tdx_payload(payload_offset, payload_size, vm_memory.deref())
            .unwrap();

        vm.load_tdx_cmdline(cmdline_offset, vm_memory.deref())
            .unwrap();

        let boot_vcpu_count = vm.vm_config().vcpu_count;
        vm.vcpu_manager()
            .unwrap()
            .create_vcpus(boot_vcpu_count, None, None, true)
            .unwrap();
        vm.vcpu_manager()
            .unwrap()
            .init_tdx_vcpus(hob_offset)
            .unwrap();

        let address_space = vm.vm_address_space().cloned().unwrap();
        vm.generate_hob_list(hob_offset, vm_memory.deref(), address_space, payload_info)
            .unwrap();

        for section in sections {
            let host_address = vm_memory
                .deref()
                .get_host_address(GuestAddress(section.address))
                .unwrap();

            vm.init_tdx_memory(
                host_address as u64,
                section.address,
                section.size,
                section.attributes,
            )
            .unwrap();
        }

        vm.finalize_tdx().unwrap();

        vm.init_configure_system(&vm.vm_as().unwrap().clone()).unwrap();
        vm.init_upcall().unwrap();
        
        vm.vcpu_manager().unwrap().start_boot_vcpus(BpfProgram::default()).unwrap();
    }
}
