use libwifi_macros::AddressHeader;

use crate::frame::components::*;

use byteorder::{BigEndian, WriteBytesExt};
use std::{
    collections::HashMap,
    io::{self, Write},
    time::SystemTime,
};

#[derive(Clone, Debug, AddressHeader)]
pub struct QosData {
    pub header: DataHeader,
    pub eapol_key: Option<EapolKey>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, AddressHeader)]
pub struct QosDataCfAck {
    pub header: DataHeader,
    pub eapol_key: Option<EapolKey>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, AddressHeader)]
pub struct QosDataCfPoll {
    pub header: DataHeader,
    pub eapol_key: Option<EapolKey>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, AddressHeader)]
pub struct QosDataCfAckCfPoll {
    pub header: DataHeader,
    pub eapol_key: Option<EapolKey>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, AddressHeader)]
pub struct QosCfPoll {
    pub header: DataHeader,
}

#[derive(Clone, Debug, AddressHeader)]
pub struct QosCfAckCfPoll {
    pub header: DataHeader,
}

#[derive(Clone, Debug, AddressHeader)]
pub struct QosNull {
    pub header: DataHeader,
}

#[derive(Clone, Debug)]
pub struct EapolKey {
    pub protocol_version: u8,
    pub timestamp: SystemTime,
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
    pub fn to_bytes(&self) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();

        bytes.write_u8(self.protocol_version)?;
        bytes.write_u8(self.packet_type)?;
        bytes.write_u16::<BigEndian>(self.packet_length)?;
        bytes.write_u8(self.descriptor_type)?;
        bytes.write_u16::<BigEndian>(self.key_information)?;
        bytes.write_u16::<BigEndian>(self.key_length)?;
        bytes.write_u64::<BigEndian>(self.replay_counter)?;
        bytes.write_all(&self.key_nonce)?;
        bytes.write_all(&self.key_iv)?;
        bytes.write_u64::<BigEndian>(self.key_rsc)?;
        bytes.write_u64::<BigEndian>(self.key_id)?;
        bytes.write_all(&self.key_mic)?;
        bytes.write_u16::<BigEndian>(self.key_data_length)?;
        bytes.write_all(&self.key_data)?;

        Ok(bytes)
    }

    pub fn determine_key_type(&mut self) -> MessageType {
        /*
        00000001 00001010
        xxx..... ........ Reserved
        ...0.... ........ Key Data Not Encrypted
        ....0... ........ No Request to initiate Handshake
        .....0.. ........ No Error
        ......0. ........ Not Secure
        .......1 ........ Message contains Key MIC
        ........ 0....... No Key ACK
        ........ .0...... Install: 802.1X component shall not configure the temporal key
        ........ ..xx.... Reserved
        ........ ....1... Key Type: Pairwise Key
        ........ .....010 Vers: HMAC-SHA1-128 is the EAPOL-Key MIC / NIST AES key wrap is the EAPOL-key enc
        */
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
            // KEY_ACK == 1
            ki if ki & KEY_ACK != 0
                && ki & KEY_MIC == 0
                && ki & SECURE == 0
                && ki & INSTALL == 0 =>
            {
                MessageType::Message1
            }
            // Check for Message 2 of 4-way handshake
            // KEY_MIC == 1
            ki if ki & KEY_ACK == 0
                && ki & KEY_MIC != 0
                && ki & SECURE == 0
                && ki & INSTALL == 0 =>
            {
                MessageType::Message2
            }
            // Check for Message 3 of 4-way handshake
            // KEY_ACK & KEY_MIC & SECURE & AND INSTALL == 1
            ki if ki & KEY_ACK != 0
                && ki & KEY_MIC != 0
                && ki & SECURE != 0
                && ki & INSTALL != 0 =>
            {
                MessageType::Message3
            }
            // Check for Message 4 of 4-way handshake
            // KEY MIC & KEY SECURE == 1
            ki if ki & KEY_ACK == 0
                && ki & KEY_MIC != 0
                && ki & SECURE != 0
                && ki & INSTALL == 0 =>
            {
                MessageType::Message4
            }
            // Other cases, such as Group Key Handshake, or unrecognized/invalid key information
            _ => MessageType::Error,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MessageType {
    Message1,
    Message2,
    Message3,
    Message4,
    Error,
}

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageType::Message1 => write!(f, "Message 1"),
            MessageType::Message2 => write!(f, "Message 2"),
            MessageType::Message3 => write!(f, "Message 3"),
            MessageType::Message4 => write!(f, "Message 4"),
            MessageType::Error => write!(f, "Unknown Message"),
        }
    }
}
