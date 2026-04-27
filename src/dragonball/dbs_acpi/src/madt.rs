// Copyright (c) 2026 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use vm_memory::ByteValued;

#[repr(u8)]
#[derive(Default, Copy, Clone)]
pub enum MadtEntryType {
    #[default]
    LocalApic,
    Ioapic,
    InterruptSourceOverride,
    LocalX2Apic = 9,
}

#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct MadtBody {
    pub apic_address: u32,
    pub flags: u32,
}

impl MadtBody {
    pub fn new(
        apic_address: u32,
        flags: u32,
    ) -> Self {
        Self {
            apic_address,
            flags,
        }
    }
}

#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct MadtEntryLocalApic {
    pub r#type: MadtEntryType,
    pub length: u8,
    pub processor_id: u8,
    pub apic_id: u8,
    pub flags: u32,
}

impl MadtEntryLocalApic {
    pub fn new(processor_id: u8, flags: u32) -> Self {
        Self {
            r#type: MadtEntryType::LocalApic,
            length: 8,
            processor_id,
            apic_id: processor_id,
            flags,
        }
    }
}

#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct MadtEntryIoapic {
    pub r#type: MadtEntryType,
    pub length: u8,
    pub ioapic_id: u8,
    pub reserved: u8,
    pub ioapic_address: u32,
    pub gsi_base: u32,
}

impl MadtEntryIoapic {
    pub fn new(ioapic_id: u8, ioapic_address: u32, gsi_base: u32) -> Self {
        Self {
            r#type: MadtEntryType::Ioapic,
            length: 12,
            ioapic_id,
            reserved: 0,
            ioapic_address,
            gsi_base,
        }
    }
}

#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct MadtEntryIntrSrcOverride {
    pub r#type: MadtEntryType,
    pub length: u8,
    pub bus_source: u8,
    pub irq_source: u8,
    pub gsi: u32,
    pub flags: u16,
}

impl MadtEntryIntrSrcOverride {
    pub fn new(bus_source: u8, irq_source: u8, gsi: u32, flags: u16) -> Self {
        Self {
            r#type: MadtEntryType::InterruptSourceOverride,
            length: 10,
            bus_source,
            irq_source,
            gsi,
            flags,
        }
    }
}

unsafe impl ByteValued for MadtBody {}
unsafe impl ByteValued for MadtEntryLocalApic {}
unsafe impl ByteValued for MadtEntryIoapic {}
unsafe impl ByteValued for MadtEntryIntrSrcOverride {}
