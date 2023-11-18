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
    pub protocol_version: u8,
    pub packet_type: u8,
    pub packet_length: u16,
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

impl EapolKey {
    pub fn determine_key_type(&mut self) -> &'static str {
        // Define the bit masks for the relevant bits in the key_information field
        const KEY_ACK: u16 = 1 << 7;
        const KEY_MIC: u16 = 1 << 8;
        const SECURE: u16 = 1 << 9;
        const INSTALL: u16 = 1 << 6;
        /* println!(
            "KEY ACK: {:?} KEY MIC: {:?} SECURE: {:?} INSTALL: {:?} ",
            (key_information & KEY_ACK) != 0,
            (key_information & KEY_MIC) != 0,
            (key_information & SECURE) != 0,
            (key_information & INSTALL) != 0
        ); */

        match self.key_information {
            // Check for Message 1 of 4-way handshake
            ki if ki & KEY_ACK != 0
                && ki & KEY_MIC == 0
                && ki & SECURE == 0
                && ki & INSTALL == 0 =>
            {
                "Message 1"
            }
            // Check for Message 2 of 4-way handshake
            ki if ki & KEY_ACK == 0
                && ki & KEY_MIC != 0
                && ki & SECURE == 0
                && ki & INSTALL == 0 =>
            {
                "Message 2"
            }
            // Check for Message 3 of 4-way handshake
            ki if ki & KEY_ACK != 0
                && ki & KEY_MIC != 0
                && ki & SECURE != 0
                && ki & INSTALL != 0 =>
            {
                "Message 3"
            }
            // Check for Message 4 of 4-way handshake
            ki if ki & KEY_ACK == 0
                && ki & KEY_MIC != 0
                && ki & SECURE != 0
                && ki & INSTALL == 0 =>
            {
                "Message 4"
            }
            // Other cases, such as Group Key Handshake, or unrecognized/invalid key information
            _ => "Unknown or Invalid Key Information",
        }
    }
}
