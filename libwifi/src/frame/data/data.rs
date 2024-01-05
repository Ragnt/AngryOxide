use libwifi_macros::AddressHeader;

use crate::frame::components::*;

use super::{DataFrame, EapolKey, NullDataFrame};

#[derive(Clone, Debug, AddressHeader)]
pub struct Data {
    pub header: DataHeader,
    pub eapol_key: Option<EapolKey>,
    pub data: Vec<u8>,
}

impl Data {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize header
        bytes.extend_from_slice(&self.header.encode());

        let eapol_llc_header: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e];

        // Serialize EAPOL key if present
        if let Some(eapol_key) = &self.eapol_key {
            bytes.extend(eapol_llc_header);
            bytes.extend(eapol_key.encode().unwrap()); // Unwrap the result
        }

        // Append data
        bytes.extend_from_slice(&self.data);

        bytes
    }
}

impl DataFrame for Data {
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
pub struct DataCfAck {
    pub header: DataHeader,
    pub eapol_key: Option<EapolKey>,
    pub data: Vec<u8>,
}

impl DataFrame for DataCfAck {
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
pub struct DataCfPoll {
    pub header: DataHeader,
    pub eapol_key: Option<EapolKey>,
    pub data: Vec<u8>,
}

impl DataFrame for DataCfPoll {
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
pub struct DataCfAckCfPoll {
    pub header: DataHeader,
    pub eapol_key: Option<EapolKey>,
    pub data: Vec<u8>,
}

impl DataFrame for DataCfAckCfPoll {
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
pub struct CfAck {
    pub header: DataHeader,
}

impl NullDataFrame for CfAck {
    fn header(&self) -> &DataHeader {
        &self.header
    }
}

#[derive(Clone, Debug, AddressHeader)]
pub struct CfPoll {
    pub header: DataHeader,
}

impl NullDataFrame for CfPoll {
    fn header(&self) -> &DataHeader {
        &self.header
    }
}

#[derive(Clone, Debug, AddressHeader)]
pub struct CfAckCfPoll {
    pub header: DataHeader,
}

impl NullDataFrame for CfAckCfPoll {
    fn header(&self) -> &DataHeader {
        &self.header
    }
}

#[derive(Clone, Debug, AddressHeader)]
pub struct NullData {
    pub header: DataHeader,
}

impl NullDataFrame for NullData {
    fn header(&self) -> &DataHeader {
        &self.header
    }
}
