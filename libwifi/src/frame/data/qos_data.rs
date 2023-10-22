use libwifi_macros::AddressHeader;

use crate::frame::components::*;

#[derive(Clone, Debug, AddressHeader)]
pub struct QosData {
    pub header: DataHeader,
    pub eapol_key: Option<EapolKey>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, AddressHeader)]
pub struct QosNull {
    pub header: DataHeader,
}
#[derive(Clone, Debug)]
pub struct EapolKey {
    pub descriptor_type: u8,
    pub key_information: u16,
    pub key_length: u16,
    pub replay_counter: u64,
    pub key_nonce: [u8; 32],
    pub key_iv: [u8; 16],
    pub key_rsc: u64,
    pub key_id: u64,
    pub key_mic: [u8; 16],
    pub key_data_length: u16,
    pub key_data: Vec<u8>,
}
