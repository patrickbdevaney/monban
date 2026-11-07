/// Deliberate faults.
#[derive(Default)]
pub struct Faults {
    pub wrong_jws_key: bool,
}

pub(super) fn wrong_jws_key(cfg: &super::AcmeConfig) -> bool {
    cfg.faults.wrong_jws_key
}
