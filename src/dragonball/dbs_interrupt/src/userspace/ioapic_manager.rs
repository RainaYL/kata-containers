// Copyright (c) 2026 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use kvm_ioctls::VmFd;

use std::sync::Arc;

#[cfg(feature = "split-legacy-irq")]
use super::legacy_irq::*;
use super::{
    ioapic::*, InterruptIndex, InterruptManager, InterruptSourceGroup, InterruptSourceType, Result,
};

/// IOAPIC manager that manages userspace interrupt routing
pub struct IoapicManager {
    ioregsel: IoRegSel,
    ioapicid: IoapicId,
    ioapicver: IoapicVer,
    ioapicarb: IoapicArb,
    ioapic_boot_config: IoapicBootConfig,
    #[cfg(feature = "split-legacy-irq")]
    irqs: Vec<Arc<UserspaceLegacyIrqObj>>,
}

impl IoapicManager {
    /// Create a new IOAPIC manager instance
    pub fn create_ioapic_manager(
        vmfd: Arc<VmFd>,
        version: u8,
        nr_redir_entries: InterruptIndex,
    ) -> Result<Self> {
        if nr_redir_entries > IOAPIC_MAX_NR_REDIR_ENTRIES {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }

        let mut ioapicver = IoapicVer::default();
        ioapicver.set_version(version);
        ioapicver.set_entries(nr_redir_entries as u8 - 1);

        #[cfg(feature = "split-legacy-irq")]
        let irqs = {
            let mut irqs = Vec::with_capacity(nr_redir_entries as usize);
            for i in 0..nr_redir_entries {
                irqs.push(Arc::new(UserspaceLegacyIrqObj::new(i, vmfd.clone())));
            }
            irqs
        };

        Ok(Self {
            ioregsel: IoRegSel::default(),
            ioapicid: IoapicId::default(),
            ioapicver,
            ioapicarb: IoapicArb::default(),
            ioapic_boot_config: IoapicBootConfig::default(),
            #[cfg(feature = "split-legacy-irq")]
            irqs,
        })
    }

    /// Create a new IOAPIC manager instance with default version and redirection table size
    pub fn create_default_ioapic_manager(vmfd: Arc<VmFd>) -> Result<Self> {
        Self::create_ioapic_manager(
            vmfd,
            IOAPIC_DEFAULT_VERSION,
            IOAPIC_DEFAULT_NR_REDIR_ENTRIES,
        )
    }

    /// Get IOREGSEL register
    pub fn ioregsel(&self) -> u32 {
        self.ioregsel.clone().into()
    }

    /// Update IOREGSEL register
    pub fn set_ioregsel(&mut self, val: u32) -> Result<()> {
        let val = IoRegSel::from(val);
        let select = val.register_index();
        if !(select == IOAPIC_IOAPICID_INDEX
            || select == IOAPIC_IOAPICVER_INDEX
            || select == IOAPIC_IOAPICARB_INDEX
            || select == IOAPIC_BOOT_CONFIGURATION
            || (select >= IOAPIC_REDIR_TABLE_START_INDEX
                && select < IOAPIC_REDIR_TABLE_START_INDEX + 2 * self.nr_redir_entries() as u8))
        {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }

        self.ioregsel = val;

        Ok(())
    }

    /// Get value from IOAPIC data registers
    pub fn iowin(&self) -> u32 {
        match self.ioregsel.register_index() {
            IOAPIC_IOAPICID_INDEX => self.ioapicid.clone().into(),
            IOAPIC_IOAPICVER_INDEX => self.ioapicver.clone().into(),
            IOAPIC_IOAPICARB_INDEX => self.ioapicarb.clone().into(),
            IOAPIC_BOOT_CONFIGURATION => self.ioapic_boot_config.clone().into(),
            // We haved checked the validity of ioregsel while setting, therefore all values beyond the four
            // special IOAPIC registers above would become a valid redirection entry
            index => {
                #[cfg(feature = "split-legacy-irq")]
                {
                    let offset = (index - IOAPIC_REDIR_TABLE_START_INDEX) as usize;
                    let is_low = (offset & 0x1) == 0;
                    let irq_base = offset >> 1;

                    if is_low {
                        self.irqs[irq_base].redir_entry_low().into()
                    } else {
                        self.irqs[irq_base].redir_entry_high().into()
                    }
                }
                #[cfg(not(feature = "split-legacy-irq"))]
                0
            }
        }
    }

    /// Update IOAPIC data registers
    pub fn set_iowin(&mut self, val: u32) -> Result<()> {
        match self.ioregsel.register_index() {
            IOAPIC_IOAPICID_INDEX => {
                self.ioapicid = IoapicId::from(val);
                Ok(())
            }
            IOAPIC_IOAPICVER_INDEX => {
                // IOAPICVER register is read-only
                Err(std::io::Error::from_raw_os_error(libc::EINVAL))
            }
            IOAPIC_IOAPICARB_INDEX => {
                self.ioapicarb = IoapicArb::from(val);
                Ok(())
            }
            IOAPIC_BOOT_CONFIGURATION => {
                self.ioapic_boot_config = IoapicBootConfig::from(val);
                Ok(())
            }
            // We haved checked the validity of ioregsel while setting, therefore all values beyond the four
            // special IOAPIC registers above would become a valid redirection entry
            index => {
                #[cfg(feature = "split-legacy-irq")]
                {
                    let offset = (index - IOAPIC_REDIR_TABLE_START_INDEX) as usize;
                    let is_low = (offset & 0x1) == 0;
                    let irq_base = offset >> 1;

                    if is_low {
                        self.irqs[irq_base].set_redir_entry_low(IoapicRedirEntryLow::from(val));
                    } else {
                        self.irqs[irq_base].set_redir_entry_high(IoapicRedirEntryHigh::from(val));
                    }
                }

                Ok(())
            }
        }
    }

    #[cfg(feature = "split-legacy-irq")]
    /// Deassert level for a level-triggered irq
    pub fn deassert_level(&self, base: InterruptIndex) -> Result<()> {
        let irq = self
            .get_legacy_irq(base)
            .ok_or(std::io::Error::from_raw_os_error(libc::EINVAL))?;
        if !irq.is_level() {
            return Ok(());
        }
        irq.set_level_high(false);
        Ok(())
    }

    #[cfg(feature = "split-legacy-irq")]
    /// Try delivering an interrupt for a given irq base
    pub fn try_deliver(&self, base: InterruptIndex) -> Result<()> {
        let irq = self
            .get_legacy_irq(base)
            .ok_or(std::io::Error::from_raw_os_error(libc::EINVAL))?;
        irq.try_deliver()
    }

    #[cfg(feature = "split-legacy-irq")]
    /// Get a legacy irq instance given irq base
    pub fn get_legacy_irq(&self, base: InterruptIndex) -> Option<Arc<UserspaceLegacyIrqObj>> {
        if base >= self.nr_redir_entries() {
            return None;
        }

        Some(self.irqs[base as usize].clone())
    }

    fn nr_redir_entries(&self) -> InterruptIndex {
        self.ioapicver.entries() as InterruptIndex + 1
    }
}

impl InterruptManager for IoapicManager {
    fn create_group(
        &self,
        ty: InterruptSourceType,
        base: InterruptIndex,
        count: u32,
    ) -> Result<Arc<Box<dyn InterruptSourceGroup>>> {
        let group = match ty {
            #[cfg(feature = "split-legacy-irq")]
            InterruptSourceType::LegacyIrq => {
                if count != 1 {
                    return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
                }
                let irq = self
                    .get_legacy_irq(base)
                    .ok_or(std::io::Error::from_raw_os_error(libc::EINVAL))?;
                let group: Arc<Box<dyn InterruptSourceGroup>> =
                    Arc::new(Box::new(UserspaceLegacyIrq::new(irq)));
                group
            }
            _ => {
                return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
            }
        };

        Ok(group)
    }

    fn destroy_group(&self, _group: Arc<Box<dyn InterruptSourceGroup>>) -> Result<()> {
        Ok(())
    }
}
