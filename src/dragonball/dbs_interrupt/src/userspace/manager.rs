// Copyright (c) 2026 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use kvm_ioctls::VmFd;

use std::convert::TryInto;
use std::sync::{Arc, RwLock};

#[cfg(feature = "split-legacy-irq")]
use super::legacy_irq::*;
use super::{
    ioapic::*, InterruptIndex, InterruptManager, InterruptSourceGroup, InterruptSourceType, Result,
};

/// Structure to manage interrupt sources for a virtual machine in userspace based on IOAPIC
/// protocol.
///
/// The structure emulates IOAPIC registers, and allows for editing specific IOAPIC entries via
/// MMIO calls.
pub struct UserspaceIoapicManager {
    ioregsel: RwLock<IoRegSel>,
    ioapicid: RwLock<IoapicId>,
    // IoapicVer register is read-only
    ioapicver: IoapicVer,
    ioapicarb: RwLock<IoapicArb>,
    #[cfg(feature = "split-legacy-irq")]
    irqs: Vec<Arc<UserspaceLegacyIrqObj>>,
}

impl UserspaceIoapicManager {
    /// Create a new IOAPIC manager instance
    pub fn create_ioapic_manager(
        vmfd: Arc<VmFd>,
        version: u8,
        nr_redir_entries: InterruptIndex,
    ) -> Result<Self> {
        if nr_redir_entries == 0 || nr_redir_entries > IOAPIC_MAX_NR_REDIR_ENTRIES {
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
            ioregsel: RwLock::new(IoRegSel::default()),
            ioapicid: RwLock::new(IoapicId::default()),
            ioapicver,
            ioapicarb: RwLock::new(IoapicArb::default()),
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

    fn ioregsel(&self) -> u32 {
        self.ioregsel.read().unwrap().clone().into()
    }

    fn set_ioregsel(&self, val: u32) -> Result<()> {
        let val = IoRegSel::from(val);
        let select = val.register_index();
        if !(select == IOAPIC_IOAPICID_INDEX
            || select == IOAPIC_IOAPICVER_INDEX
            || select == IOAPIC_IOAPICARB_INDEX
            || (select >= IOAPIC_REDIR_TABLE_START_INDEX
                && select < IOAPIC_REDIR_TABLE_START_INDEX + 2 * self.nr_redir_entries() as u8))
        {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }

        *self.ioregsel.write().unwrap() = val;

        Ok(())
    }

    fn iowin(&self) -> u32 {
        match self.ioregsel.read().unwrap().register_index() {
            IOAPIC_IOAPICID_INDEX => self.ioapicid.read().unwrap().clone().into(),
            IOAPIC_IOAPICVER_INDEX => self.ioapicver.clone().into(),
            IOAPIC_IOAPICARB_INDEX => self.ioapicarb.read().unwrap().clone().into(),
            // We have checked the validity of ioregsel while setting, therefore all values beyond the
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

    fn set_iowin(&self, val: u32) -> Result<()> {
        match self.ioregsel.read().unwrap().register_index() {
            IOAPIC_IOAPICID_INDEX => {
                *self.ioapicid.write().unwrap() = IoapicId::from(val);
                Ok(())
            }
            IOAPIC_IOAPICVER_INDEX => {
                // IOAPICVER register is read-only
                Err(std::io::Error::from_raw_os_error(libc::EINVAL))
            }
            IOAPIC_IOAPICARB_INDEX => {
                *self.ioapicarb.write().unwrap() = IoapicArb::from(val);
                Ok(())
            }
            // We have checked the validity of ioregsel while setting, therefore all values beyond the four
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

    fn nr_redir_entries(&self) -> InterruptIndex {
        self.ioapicver.entries() as InterruptIndex + 1
    }
}

impl InterruptManager for UserspaceIoapicManager {
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
                if base >= self.nr_redir_entries() {
                    return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
                }
                // Irq has already been created while initializing the manager, so we
                // only return the corresponding entry here.
                let irq = self.irqs[base as usize].clone();
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

    fn ioapic_read(&self, addr: u64, data: &mut [u8]) -> Result<()> {
        if data.len() != 4 {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }

        let mut val = 0;

        if addr == IOAPIC_IOREGSEL_BASE as u64 {
            val = self.ioregsel();
        } else if addr == IOAPIC_IOWIN_BASE as u64 {
            val = self.iowin();
        }

        data.copy_from_slice(&val.to_le_bytes());

        Ok(())
    }

    fn ioapic_write(&self, addr: u64, data: &[u8]) -> Result<()> {
        if data.len() != 4 {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }

        // Safe because we have checked that the length of data is 32 bits
        let val = u32::from_le_bytes(data.try_into().expect("length checked to be 4"));

        if addr == IOAPIC_IOREGSEL_BASE as u64 {
            self.set_ioregsel(val)?;
        } else if addr == IOAPIC_IOWIN_BASE as u64 {
            self.set_iowin(val)?;
        }

        Ok(())
    }
}
