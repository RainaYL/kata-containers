use vm_memory::ByteValued;

pub struct Sdt {
    data: Vec<u8>,
}

impl Sdt {
    pub fn new(header: &[u8]) -> Self {
        let mut sdt = Self {
            data: Vec::new(),
        };
        sdt.data.extend_from_slice(header);
        sdt.update_length();
        sdt.update_checksum();
        sdt
    }

    pub fn append(&mut self, entry: &[u8]) {
        self.data.extend_from_slice(entry);
        self.update_length();
        self.update_checksum();
    }

    pub fn as_slice(&self) -> &[u8] {
        self.data.as_slice()
    }

    fn update_length(&mut self) {
        let length = self.data.len() as u32;
        unsafe {
            *((self.data.as_mut_ptr() as usize + 4) as *mut u32) = length;
        }
    }

    fn update_checksum(&mut self) {
        let checksum = super::calculate_checksum(self.data.as_slice());
        self.data[9] = checksum;
    }
}

#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct GenericSdtHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: u32,
    pub creator_id: [u8; 4],
    pub creator_revision: u32,
}

#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of GenericSdtHeader"][::std::mem::size_of::<GenericSdtHeader>() - 36usize];
    ["Offset of field: GenericSdtHeader::signature"]
        [::std::mem::offset_of!(GenericSdtHeader, signature) - 0usize];
    ["Offset of field: GenericSdtHeader::length"]
        [::std::mem::offset_of!(GenericSdtHeader, length) - 4usize];
    ["Offset of field: GenericSdtHeader::revision"]
        [::std::mem::offset_of!(GenericSdtHeader, revision) - 8usize];
    ["Offset of field: GenericSdtHeader::checksum"]
        [::std::mem::offset_of!(GenericSdtHeader, checksum) - 9usize];
    ["Offset of field: GenericSdtHeader::oem_id"]
        [::std::mem::offset_of!(GenericSdtHeader, oem_id) - 10usize];
    ["Offset of field: GenericSdtHeader::oem_table_id"]
        [::std::mem::offset_of!(GenericSdtHeader, oem_table_id) - 16usize];
    ["Offset of field: GenericSdtHeader::oem_revision"]
        [::std::mem::offset_of!(GenericSdtHeader, oem_revision) - 24usize];
    ["Offset of field: GenericSdtHeader::creator_id"]
        [::std::mem::offset_of!(GenericSdtHeader, creator_id) - 28usize];
    ["Offset of field: GenericSdtHeader::creator_revision"]
        [::std::mem::offset_of!(GenericSdtHeader, creator_revision) - 32usize];
};

unsafe impl ByteValued for GenericSdtHeader {}

impl GenericSdtHeader {
    pub fn new(signature: [u8; 4], length: u32, revision: u8) -> Self {
        Self {
            signature,
            length,
            revision,
            checksum: 0,
            oem_id: *b"DGBALL",
            oem_table_id: *b"KATADBS ",
            oem_revision: 1,
            creator_id: *b"KATA",
            creator_revision: 1,
        }
    }

    pub fn set_checksum(&mut self, checksum: u8) {
        self.checksum = checksum;
    }
}
