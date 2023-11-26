use libwifi_macros::AddressHeader;

use crate::frame::components::*;

use super::{DataFrame, EapolKey, NullDataFrame};

#[derive(Clone, Debug, AddressHeader)]
pub struct Data {
    pub header: DataHeader,
    pub eapol_key: Option<EapolKey>,
    pub data: Vec<u8>,
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
