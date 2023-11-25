use libwifi_macros::AddressHeader;

use crate::frame::components::*;

use super::EapolKey;

#[derive(Clone, Debug, AddressHeader)]
pub struct Data {
    pub header: DataHeader,
    pub eapol_key: Option<EapolKey>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, AddressHeader)]
pub struct NullData {
    pub header: DataHeader,
}

#[derive(Clone, Debug, AddressHeader)]
pub struct DataCfAck {
    pub header: DataHeader,
    pub eapol_key: Option<EapolKey>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, AddressHeader)]
pub struct DataCfPoll {
    pub header: DataHeader,
    pub eapol_key: Option<EapolKey>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, AddressHeader)]
pub struct DataCfAckCfPoll {
    pub header: DataHeader,
    pub eapol_key: Option<EapolKey>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, AddressHeader)]
pub struct CfAck {
    pub header: DataHeader,
}

#[derive(Clone, Debug, AddressHeader)]
pub struct CfPoll {
    pub header: DataHeader,
}

#[derive(Clone, Debug, AddressHeader)]
pub struct CfAckCfPoll {
    pub header: DataHeader,
}
