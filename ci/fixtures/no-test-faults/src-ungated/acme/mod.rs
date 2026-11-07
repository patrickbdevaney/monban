//! FIXTURE (T5 mutant): the pre-Phase-8 layout, `Faults` public production API.
#[derive(Default)]
pub struct Faults {
    pub wrong_jws_key: bool,
}

pub struct AcmeConfig {
    pub directory_url: String,
    pub faults: Faults,
}
