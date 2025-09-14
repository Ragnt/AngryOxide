use libwifi_macros::AddressHeader;

use crate::frame::components::*;

use byteorder::{BigEndian, WriteBytesExt};
use std::{
    io::{self, Write},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone)]
pub struct PmkidError;

impl std::fmt::Display for PmkidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PMKID not found or invalid")
    }
}

impl std::error::Error for PmkidError {}

use super::{DataFrame, NullDataFrame};

#[derive(Clone, Debug, AddressHeader)]
pub struct QosData {
    pub header: DataHeader,
    pub eapol_key: Option<EapolKey>,
    pub data: Vec<u8>,
}

impl DataFrame for QosData {
    fn header(&self) -> &DataHeader {
        &self.header
    }
    fn eapol_key(&self) -> &Option<EapolKey> {
        &self.eapol_key
    }
    fn data(&self) -> &Vec<u8> {
        &self.data
    }
}

#[derive(Clone, Debug, AddressHeader)]
pub struct QosDataCfAck {
    pub header: DataHeader,
    pub eapol_key: Option<EapolKey>,
    pub data: Vec<u8>,
}

impl DataFrame for QosDataCfAck {
    fn header(&self) -> &DataHeader {
        &self.header
    }
    fn eapol_key(&self) -> &Option<EapolKey> {
        &self.eapol_key
    }
    fn data(&self) -> &Vec<u8> {
        &self.data
    }
}

#[derive(Clone, Debug, AddressHeader)]
pub struct QosDataCfPoll {
    pub header: DataHeader,
    pub eapol_key: Option<EapolKey>,
    pub data: Vec<u8>,
}

impl DataFrame for QosDataCfPoll {
    fn header(&self) -> &DataHeader {
        &self.header
    }
    fn eapol_key(&self) -> &Option<EapolKey> {
        &self.eapol_key
    }
    fn data(&self) -> &Vec<u8> {
        &self.data
    }
}

#[derive(Clone, Debug, AddressHeader)]
pub struct QosDataCfAckCfPoll {
    pub header: DataHeader,
    pub eapol_key: Option<EapolKey>,
    pub data: Vec<u8>,
}

impl DataFrame for QosDataCfAckCfPoll {
    fn header(&self) -> &DataHeader {
        &self.header
    }
    fn eapol_key(&self) -> &Option<EapolKey> {
        &self.eapol_key
    }
    fn data(&self) -> &Vec<u8> {
        &self.data
    }
}

#[derive(Clone, Debug, AddressHeader)]
pub struct QosCfPoll {
    pub header: DataHeader,
}

impl NullDataFrame for QosCfPoll {
    fn header(&self) -> &DataHeader {
        &self.header
    }
}

#[derive(Clone, Debug, AddressHeader)]
pub struct QosCfAckCfPoll {
    pub header: DataHeader,
}

impl NullDataFrame for QosCfAckCfPoll {
    fn header(&self) -> &DataHeader {
        &self.header
    }
}

#[derive(Clone, Debug, AddressHeader)]
pub struct QosNull {
    pub header: DataHeader,
}

impl NullDataFrame for QosNull {
    fn header(&self) -> &DataHeader {
        &self.header
    }
}

#[derive(Clone, Debug)]
pub struct KeyInformation {
    pub descriptor_version: u8,
    pub key_type: bool,
    pub key_index: u8,
    pub install: bool,
    pub key_ack: bool,
    pub key_mic: bool,
    pub secure: bool,
    pub error: bool,
    pub request: bool,
    pub encrypted_key_data: bool,
    pub smk_message: bool,
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

impl Default for EapolKey {
    fn default() -> EapolKey {
        EapolKey {
            protocol_version: 0,
            timestamp: UNIX_EPOCH,
            packet_type: 0,
            packet_length: 0,
            descriptor_type: 0,
            key_information: 0,
            key_length: 0,
            replay_counter: 0,
            key_nonce: [0; 32],
            key_iv: [0; 16],
            key_rsc: 0,
            key_id: 0,
            key_mic: [0; 16],
            key_data_length: 0,
            key_data: Vec::new(),
        }
    }
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

    pub fn encode(&self) -> Result<Vec<u8>, std::io::Error> {
        let key_data_length = self.key_data.len() as u16;

        // Calculate the packet length dynamically
        let packet_length = 1 // descriptor_type
            + 2 // key_information
            + 2 // key_length
            + 8 // replay_counter
            + 32
            + 16
            + 8 // key_rsc
            + 8 // key_id
            + 16
            + 2 // key_data_length
            + key_data_length;

        let mut buf = Vec::new();
        buf.write_u8(self.protocol_version)?;
        buf.write_u8(self.packet_type)?;
        buf.write_u16::<BigEndian>(packet_length)?;
        buf.write_u8(self.descriptor_type)?;
        buf.write_u16::<BigEndian>(self.key_information)?;
        buf.write_u16::<BigEndian>(self.key_length)?;
        buf.write_u64::<BigEndian>(self.replay_counter)?;
        buf.extend_from_slice(&self.key_nonce);
        buf.extend_from_slice(&self.key_iv);
        buf.write_u64::<BigEndian>(self.key_rsc)?;
        buf.write_u64::<BigEndian>(self.key_id)?;
        buf.extend_from_slice(&self.key_mic);
        buf.write_u16::<BigEndian>(key_data_length)?;
        buf.extend_from_slice(&self.key_data);
        Ok(buf)
    }

    pub fn parse_key_information(&self) -> KeyInformation {
        KeyInformation {
            descriptor_version: (self.key_information & 0x0007) as u8, // Bits 0-2
            key_type: (self.key_information & 0x0008) != 0,            // Bit 3
            key_index: ((self.key_information & 0x0030) >> 4) as u8,   // Bits 4-5
            install: (self.key_information & 0x0040) != 0,             // Bit 6
            key_ack: (self.key_information & 0x0080) != 0,             // Bit 7
            key_mic: (self.key_information & 0x0100) != 0,             // Bit 8
            secure: (self.key_information & 0x0200) != 0,              // Bit 9
            error: (self.key_information & 0x0400) != 0,               // Bit 10
            request: (self.key_information & 0x0800) != 0,             // Bit 11
            encrypted_key_data: (self.key_information & 0x1000) != 0,  // Bit 12
            smk_message: (self.key_information & 0x2000) != 0,         // Bit 13
        }
    }

    pub fn determine_key_type(&self) -> MessageType {
        /*
        00000001 00001010
        xxx..... ........ Reserved
        ...0.... ........ Key Data Not Encrypted
        ....0... ........ No Request to initiate Handshake
        .....0.. ........ No Error
        ......0. ........ Not Secure
        .......0 ........ Message contains Key MIC
        ........ 1....... No Key ACK
        ........ .0...... Install: 802.1X component shall not configure the temporal key
        ........ ..xx.... Reserved
        ........ ....1... Key Type: Pairwise Key
        ........ .....010 Vers: HMAC-SHA1-128 is the EAPOL-Key MIC / NIST AES key wrap is the EAPOL-key enc
        */

        const KEY_TYPE: u16 = 1 << 3;
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

        if self.key_information & KEY_TYPE != 0 {
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
        } else {
            MessageType::GTK
        }
    }

    pub fn has_pmkid(&self) -> Result<Pmkid, PmkidError> {
        if self.determine_key_type() != MessageType::Message1 {
            return Err(PmkidError);
        }

        // Define the RSN Suite OUI for PMKID validation
        let rsnsuiteoui: [u8; 3] = [0x00, 0x0f, 0xac];

        // Check for PMKID presence and validity
        if self.key_data_length as usize == 22 {
            // Extract PMKID from the key data
            let pmkid = Pmkid::from_bytes(&self.key_data);

            if pmkid.oui == rsnsuiteoui
                && pmkid.len == 0x14
                && pmkid.oui_type == 4
                && pmkid.pmkid.iter().any(|&x| x != 0)
            {
                return Ok(pmkid);
            }
        }
        Err(PmkidError)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum MessageType {
    Message1,
    Message2,
    Message3,
    Message4,
    GTK,
    Error,
}

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageType::Message1 => write!(f, "Message 1"),
            MessageType::Message2 => write!(f, "Message 2"),
            MessageType::Message3 => write!(f, "Message 3"),
            MessageType::Message4 => write!(f, "Message 4"),
            MessageType::GTK => write!(f, "Group Temporal Key"),
            MessageType::Error => write!(f, "Unknown Message"),
        }
    }
}

// PMKID struct definition
#[derive(Debug, Clone, Copy)]
pub struct Pmkid {
    pub id: u8,
    pub len: u8,
    pub oui: [u8; 3],
    pub oui_type: u8,
    pub pmkid: [u8; 16],
}

// PMKID struct conversion implementation
impl Pmkid {
    fn from_bytes(bytes: &[u8]) -> Self {
        // Ensure the slice has the correct length
        if bytes.len() != 22 {
            panic!("Invalid PMKID data length");
        }
        let mut pmkid = Pmkid {
            id: bytes[0],
            len: bytes[1],
            oui: [bytes[2], bytes[3], bytes[4]],
            oui_type: bytes[5],
            pmkid: [0; 16],
        };
        pmkid.pmkid.copy_from_slice(&bytes[6..]);
        pmkid
    }
}
