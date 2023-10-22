use crate::frame::components::*;
use libwifi_macros::AddressHeader;

#[derive(Clone, Debug, AddressHeader)]
pub struct Authentication {
    pub header: ManagementHeader,
    pub auth_algorithm: u16,
    pub auth_seq: u16,
    pub status_code: u16,
    pub challenge_text: Option<Vec<u8>>,
}

#[derive(Clone, Debug, AddressHeader)]
pub struct Deauthentication {
    pub header: ManagementHeader,
    pub reason_code: u16,
}
