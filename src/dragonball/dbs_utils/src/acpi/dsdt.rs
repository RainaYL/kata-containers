use std::fs::File;

pub struct Dsdt {
    pub aml: File,
}

impl Dsdt {
    pub fn new(aml_path: String) -> Self {
        let aml = File::open(aml_path).unwrap();
        Self { aml }
    }
}
