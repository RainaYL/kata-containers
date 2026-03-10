use super::sdt::GenericSdtHeader;

use vm_memory::ByteValued;

#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
#[allow(non_snake_case)]
pub struct Fadt {
    pub h: GenericSdtHeader,
    pub FirmwareCtrl: u32,
    pub Dsdt: u32,
    pub Reserved: u8,
    pub PreferredPowerManagementProfile: u8,
    pub SCI_Interrupt: u16,
    pub SMI_CommandPort: u32,
    pub AcpiEnable: u8,
    pub AcpiDisable: u8,
    pub S4BIOS_REQ: u8,
    pub PSTATE_Control: u8,
    pub PM1aEventBlock: u32,
    pub PM1bEventBlock: u32,
    pub PM1aControlBlock: u32,
    pub PM1bControlBlock: u32,
    pub PM2ControlBlock: u32,
    pub PMTimerBlock: u32,
    pub GPE0Block: u32,
    pub GPE1Block: u32,
    pub PM1EventLength: u8,
    pub PM1ControlLength: u8,
    pub PM2ControlLength: u8,
    pub PMTimerLength: u8,
    pub GPE0Length: u8,
    pub GPE1Length: u8,
    pub GPE1Base: u8,
    pub CStateControl: u8,
    pub WorstC2Latency: u16,
    pub WorstC3Latency: u16,
    pub FlushSize: u16,
    pub FlushStride: u16,
    pub DutyOffset: u8,
    pub DutyWidth: u8,
    pub DayAlarm: u8,
    pub MonthAlarm: u8,
    pub Century: u8,
    pub BootArchitectureFlags: u16,
    pub Reserved2: u8,
    pub Flags: u32,
    pub ResetReg: GenericAddressStructure,
    pub ResetValue: u8,
    pub Reserved3: [u8; 3],
    pub X_FirmwareControl: u64,
    pub X_Dsdt: u64,
    pub X_PM1aEventBlock: GenericAddressStructure,
    pub X_PM1bEventBlock: GenericAddressStructure,
    pub X_PM1aControlBlock: GenericAddressStructure,
    pub X_PM1bControlBlock: GenericAddressStructure,
    pub X_PM2ControlBlock: GenericAddressStructure,
    pub X_PMTimerBlock: GenericAddressStructure,
    pub X_GPE0Block: GenericAddressStructure,
    pub X_GPE1Block: GenericAddressStructure,
}

#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
#[allow(non_snake_case)]
struct GenericAddressStructure {
    pub AddressSpace: u8,
    pub BitWidth: u8,
    pub BitOffset: u8,
    pub AccessSize: u8,
    pub Address: u64,
}

unsafe impl ByteValued for GenericAddressStructure {}
unsafe impl ByteValued for Fadt {}

impl Fadt {
    pub fn new() -> Self {
        let mut fadt = unsafe { core::mem::zeroed() };
        fadt.h = GenericSdtHeader::new(*b"FACP", core::mem::size_of::<Fadt>() as u32, 6);
        
        fadt.SCI_Interrupt = 9;

        fadt.PM1aEventBlock = 0xb000;
        fadt.PM1aControlBlock = 0xb004;
        fadt.PMTimerBlock = 0xb008;
        fadt.GPE0Block = 0xb020;

        fadt.PM1EventLength = 4;
        fadt.PM1ControlLength = 2;
        fadt.PMTimerLength = 4;
        fadt.GPE0Length = 2;

        fadt.BootArchitectureFlags = 1;
        fadt.Flags = (1 << 0) | (1 << 8) | (1 << 9) | (1 << 10);

        fadt.X_PM1aEventBlock = GenericAddressStructure {
            AddressSpace: 1,
            BitWidth: 32,
            BitOffset: 0,
            AccessSize: 3,
            Address: 0xb000,
        };
        fadt.X_PM1aControlBlock = GenericAddressStructure {
            AddressSpace: 1,
            BitWidth: 16,
            BitOffset: 0,
            AccessSize: 2,
            Address: 0xb004,
        };
        fadt.X_PMTimerBlock = GenericAddressStructure {
            AddressSpace: 1,
            BitWidth: 32,
            BitOffset: 0,
            AccessSize: 3,
            Address: 0xb008,
        };

        fadt
    }
}
