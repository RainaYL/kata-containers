use super::sdt::GenericSdtHeader;

use vm_memory::ByteValued;

/// start of IOAPIC
pub const IOAPIC_START: u32 = 0xfec0_0000;
/// IOAPIC version
pub const IOAPIC_VERSION: u32 = 0x20;
/// IOAPIC max redir entry
pub const IOAPIC_MAX_REDIR_ENTRIES: u32 = 23;
/// start of APIC
pub const APIC_START: u32 = 0xfee0_0000;

/// MADT CPU ENABLE FLAG
pub const MADT_CPU_ENABLE_FLAG: usize = 0;

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
pub struct MadtHeader {
    pub generic_header: GenericSdtHeader,
    pub apic_address: u32,
    pub flags: u32,
}

#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of MadtHeader"][::std::mem::size_of::<MadtHeader>() - 44usize];
    ["Offset of field: MadtHeader::generic_header"]
        [::std::mem::offset_of!(MadtHeader, generic_header) - 0usize];
    ["Offset of field: MadtHeader::apic_address"]
        [::std::mem::offset_of!(MadtHeader, apic_address) - 36usize];
    ["Offset of field: MadtHeader::flags"][::std::mem::offset_of!(MadtHeader, flags) - 40usize];
};

impl MadtHeader {
    pub fn new(
        apic_address: u32,
        flags: u32,
    ) -> Self {
        Self {
            generic_header: GenericSdtHeader::new(*b"APIC", 44, 5),
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

#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of MadtEntryLocalApic"][::std::mem::size_of::<MadtEntryLocalApic>() - 8usize];
    ["Offset of field: MadtEntryLocalApic::type"]
        [::std::mem::offset_of!(MadtEntryLocalApic, r#type) - 0usize];
    ["Offset of field: MadtEntryLocalApic::length"]
        [::std::mem::offset_of!(MadtEntryLocalApic, length) - 1usize];
    ["Offset of field: MadtEntryLocalApic::processor_id"]
        [::std::mem::offset_of!(MadtEntryLocalApic, processor_id) - 2usize];
    ["Offset of field: MadtEntryLocalApic::apic_id"]
        [::std::mem::offset_of!(MadtEntryLocalApic, apic_id) - 3usize];
    ["Offset of field: MadtEntryLocalApic::flags"]
        [::std::mem::offset_of!(MadtEntryLocalApic, flags) - 4usize];
};

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
    r#type: MadtEntryType,
    length: u8,
    ioapic_id: u8,
    reserved: u8,
    ioapic_address: u32,
    gsi_base: u32,
}

#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of MadtEntryLocalApic"][::std::mem::size_of::<MadtEntryIoapic>() - 12usize];
    ["Offset of field: MadtEntryIoapic::type"]
        [::std::mem::offset_of!(MadtEntryIoapic, r#type) - 0usize];
    ["Offset of field: MadtEntryIoapic::length"]
        [::std::mem::offset_of!(MadtEntryIoapic, length) - 1usize];
    ["Offset of field: MadtEntryIoapic::ioapic_id"]
        [::std::mem::offset_of!(MadtEntryIoapic, ioapic_id) - 2usize];
    ["Offset of field: MadtEntryIoapic::reserved"]
        [::std::mem::offset_of!(MadtEntryIoapic, reserved) - 3usize];
    ["Offset of field: MadtEntryIoapic::ioapic_address"]
        [::std::mem::offset_of!(MadtEntryIoapic, ioapic_address) - 4usize];
    ["Offset of field: MadtEntryIoapic::gsi_base"]
        [::std::mem::offset_of!(MadtEntryIoapic, gsi_base) - 8usize];
};

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
    r#type: MadtEntryType,
    length: u8,
    bus_source: u8,
    irq_source: u8,
    gsi: u32,
    flags: u16,
}

#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of MadtEntryIntrSrcOverride"]
        [::std::mem::size_of::<MadtEntryIntrSrcOverride>() - 10usize];
    ["Offset of field: MadtEntryIntrSrcOverride::type"]
        [::std::mem::offset_of!(MadtEntryIntrSrcOverride, r#type) - 0usize];
    ["Offset of field: MadtEntryIntrSrcOverride::length"]
        [::std::mem::offset_of!(MadtEntryIntrSrcOverride, length) - 1usize];
    ["Offset of field: MadtEntryIntrSrcOverride::bus_source"]
        [::std::mem::offset_of!(MadtEntryIntrSrcOverride, bus_source) - 2usize];
    ["Offset of field: MadtEntryIntrSrcOverride::irq_source"]
        [::std::mem::offset_of!(MadtEntryIntrSrcOverride, irq_source) - 3usize];
    ["Offset of field: MadtEntryIntrSrcOverride::gsi"]
        [::std::mem::offset_of!(MadtEntryIntrSrcOverride, gsi) - 4usize];
    ["Offset of field: MadtEntryIntrSrcOverride::flags"]
        [::std::mem::offset_of!(MadtEntryIntrSrcOverride, flags) - 8usize];
};

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

#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct MadtEntryLocalX2Apic {
    r#type: MadtEntryType,
    length: u8,
    reserved: u16,
    x2apic_id: u32,
    flags: u32,
    processor_id: u32,
}

#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of MadtEntryLocalX2Apic"][::std::mem::size_of::<MadtEntryLocalX2Apic>() - 16usize];
    ["Offset of field: MadtEntryLocalX2Apic::type"]
        [::std::mem::offset_of!(MadtEntryLocalX2Apic, r#type) - 0usize];
    ["Offset of field: MadtEntryLocalX2Apic::length"]
        [::std::mem::offset_of!(MadtEntryLocalX2Apic, length) - 1usize];
    ["Offset of field: MadtEntryLocalX2Apic::reserved"]
        [::std::mem::offset_of!(MadtEntryLocalX2Apic, reserved) - 2usize];
    ["Offset of field: MadtEntryLocalX2Apic::x2apic_id"]
        [::std::mem::offset_of!(MadtEntryLocalX2Apic, x2apic_id) - 4usize];
    ["Offset of field: MadtEntryLocalX2Apic::flags"]
        [::std::mem::offset_of!(MadtEntryLocalX2Apic, flags) - 8usize];
    ["Offset of field: MadtEntryLocalX2Apic::processor_id"]
        [::std::mem::offset_of!(MadtEntryLocalX2Apic, processor_id) - 12usize];
};

impl MadtEntryLocalX2Apic {
    pub fn new(processor_id: u32, flags: u32) -> Self {
        Self {
            r#type: MadtEntryType::LocalX2Apic,
            length: 16,
            reserved: 0,
            // TODO: Calculate x2apic id from processor id
            x2apic_id: processor_id,
            flags,
            processor_id,
        }
    }
}

unsafe impl ByteValued for MadtHeader {}
unsafe impl ByteValued for MadtEntryLocalApic {}
unsafe impl ByteValued for MadtEntryIoapic {}
unsafe impl ByteValued for MadtEntryIntrSrcOverride {}
unsafe impl ByteValued for MadtEntryLocalX2Apic {}

#[derive(Default, Copy, Clone)]
pub struct IoapicRedirEntry {
    pub low: u32,
    pub high: u32,
}

pub struct IoapicRegisters {
    pub ioapic_select: u32,
    pub ioapic_version: u32,
    pub max_redir_entries: u32,
    pub redir_table_entries: Vec<IoapicRedirEntry>,
}

impl Default for IoapicRegisters {
    fn default() -> Self {
        let mut registers = Self {
            ioapic_select: 0,
            ioapic_version: IOAPIC_VERSION,
            max_redir_entries: IOAPIC_MAX_REDIR_ENTRIES,
            redir_table_entries: Vec::with_capacity(IOAPIC_MAX_REDIR_ENTRIES as usize),
        };
        for _ in 0..IOAPIC_MAX_REDIR_ENTRIES {
            registers.redir_table_entries.push(IoapicRedirEntry::default());
        }
        registers
    }
}

impl IoapicRegisters {
    pub fn get_redir_entry(&self, idx: usize) -> IoapicRedirEntry {
        self.redir_table_entries[idx]
    }
}

impl IoapicRedirEntry {
    pub fn get_vector(&self) -> u32 {
        self.low & 0xff
    }

    pub fn is_masked(&self) -> bool {
        ((self.low >> 16) & 1) == 1
    }

    pub fn get_apicid(&self) -> u32 {
        (self.high >> 24) & 0xff
    }

    pub fn get_trigger_mode(&self) -> u32 {
        (self.low >> 15) & 1
    }

    pub fn get_delivery_mode(&self) -> u32 {
        (self.low >> 8) & 0x7
    }

    pub fn get_dest_mode(&self) -> u32 {
        (self.low >> 11) & 0x1
    }
}
