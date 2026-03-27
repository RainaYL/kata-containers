// Copyright (c) 2026 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use kvm_bindings::kvm_msi;
use kvm_ioctls::VmFd;

use std::sync::RwLock;

use super::{ioapic::*, *};

#[derive(Debug)]
pub struct UserspaceLegacyIrq {
    base: InterruptIndex,
    vmfd: Arc<VmFd>,
    enabled: RwLock<bool>,
    pending: RwLock<bool>,
    servicing: RwLock<bool>,
    level_high: RwLock<bool>,
    redir_entry: RwLock<IoapicRedirEntry>,
}

impl UserspaceLegacyIrq {
    pub fn try_deliver(&self) -> Result<()> {
        let is_level = self.is_level();

        if self.masked() {
            return Ok(());
        }

        if is_level {
            if self.servicing() {
                return Ok(());
            }

            if !self.level_high() {
                self.set_pending(false);
                return Ok(());
            }
        }

        self.signal_msi()?;

        if is_level {
            self.set_pending(false);
            self.set_servicing(true);
        }

        Ok(())
    }

    pub(super) fn new(base: u32, count: InterruptIndex, vmfd: Arc<VmFd>) -> Result<Self> {
        if count != 1 {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }

        Ok(Self {
            base,
            vmfd,
            enabled: RwLock::new(false),
            pending: RwLock::new(false),
            servicing: RwLock::new(false),
            level_high: RwLock::new(false),
            redir_entry: RwLock::new(IoapicRedirEntry::default()),
        })
    }

    pub(super) fn redir_entry_low(&self) -> IoapicRedirEntryLow {
        self.redir_entry.read().unwrap().low().clone()
    }

    pub(super) fn redir_entry_high(&self) -> IoapicRedirEntryHigh {
        self.redir_entry.read().unwrap().high().clone()
    }

    pub(super) fn set_redir_entry_low(&mut self, entry: IoapicRedirEntryLow) {
        self.redir_entry.write().unwrap().set_low(entry);
    }

    pub(super) fn set_redir_entry_high(&mut self, entry: IoapicRedirEntryHigh) {
        self.redir_entry.write().unwrap().set_high(entry);
    }

    fn enabled(&self) -> bool {
        *self.enabled.read().unwrap()
    }

    fn set_enabled(&self, enabled: bool) {
        *self.enabled.write().unwrap() = enabled;
    }

    fn pending(&self) -> bool {
        *self.pending.read().unwrap()
    }

    fn set_pending(&self, pending: bool) {
        *self.pending.write().unwrap() = pending;
    }

    fn servicing(&self) -> bool {
        *self.servicing.read().unwrap()
    }

    fn set_servicing(&self, servicing: bool) {
        *self.servicing.write().unwrap() = servicing;
    }

    fn level_high(&self) -> bool {
        *self.level_high.read().unwrap()
    }

    fn set_level_high(&self, level_high: bool) {
        *self.level_high.write().unwrap() = level_high;
    }

    fn masked(&self) -> bool {
        self.redir_entry.read().unwrap().low().masked()
    }

    fn set_masked(&self, masked: bool) {
        self.redir_entry.write().unwrap().low().set_masked(masked);
    }

    fn is_level(&self) -> bool {
        self.redir_entry.read().unwrap().low().is_level()
    }

    fn signal_msi(&self) -> Result<()> {
        let mut address_lo = MsiAddressLow::default();
        address_lo.set_dest_mode_logical(self.redir_entry_low().dest_mode_logical());
        address_lo.set_virt_destid_8_14(self.redir_entry_high().virt_destid_8_14());
        address_lo.set_destid_0_7(self.redir_entry_high().destid_0_7());
        address_lo.set_base_address(MSI_BASE_ADDR.into());

        let mut data = MsiData::default();
        data.set_vector(self.redir_entry_low().vector());
        data.set_delivery_mode(self.redir_entry_low().delivery_mode());
        data.set_dest_mode_logical(self.redir_entry_low().dest_mode_logical());
        data.set_active_low(self.redir_entry_low().active_low());
        data.set_is_level(self.redir_entry_low().is_level());

        let kvm_msi = kvm_msi {
            address_lo: address_lo.into(),
            data: data.into(),
            ..Default::default()
        };

        let ret = self.vmfd.signal_msi(kvm_msi)?;
        if ret < 0 {
            return Err(std::io::Error::from_raw_os_error(-ret));
        }

        Ok(())
    }
}

impl InterruptSourceGroup for UserspaceLegacyIrq {
    fn interrupt_type(&self) -> InterruptSourceType {
        InterruptSourceType::LegacyIrq
    }

    fn len(&self) -> u32 {
        1
    }

    fn base(&self) -> u32 {
        self.base
    }

    fn enable(&self, configs: &[InterruptSourceConfig]) -> Result<()> {
        if configs.len() != 1 {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }

        self.set_enabled(true);

        Ok(())
    }

    fn disable(&self) -> Result<()> {
        self.set_enabled(false);

        Ok(())
    }

    fn update(&self, index: InterruptIndex, _config: &InterruptSourceConfig) -> Result<()> {
        // Update of redirection entries would be handled by IOAPIC manager via MMIO write
        // No-op here.
        if index != 0 {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }
        Ok(())
    }

    fn notifier(&self, _index: InterruptIndex) -> Option<&EventFd> {
        // KVM would not manage irqfd for split irqchip, and interrupts cannot be injected
        // via writing to irqfd.
        // Therefore, we maintain no irqfd here.
        None
    }

    fn trigger(&self, index: InterruptIndex) -> Result<()> {
        if index != 0 {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }

        if !self.enabled() {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }

        if self.is_level() {
            self.set_level_high(true);
            self.set_pending(true);
        }

        self.try_deliver()
    }

    fn mask(&self, index: InterruptIndex) -> Result<()> {
        if index != 0 {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }

        self.set_masked(true);

        Ok(())
    }

    fn unmask(&self, index: InterruptIndex) -> Result<()> {
        if index != 0 {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }
        
        self.set_masked(false);

        Ok(())
    }

    fn get_pending_state(&self, index: InterruptIndex) -> bool {
        if index != 0 {
            return false;
        }

        self.pending()
    }
}
