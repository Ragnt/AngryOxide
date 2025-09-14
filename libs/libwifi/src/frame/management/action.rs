use libwifi_macros::AddressHeader;

use crate::frame::components::*;

#[derive(Clone, Debug, AddressHeader)]
pub struct Action {
    pub header: ManagementHeader,
    pub category: ActionCategory,
    pub action: u8,
    pub station_info: StationInfo,
}

#[derive(Clone, Debug)]
pub enum ActionCategory {
    SpectrumManagement,
    Qos,
    Reserved,
    BlockAck,
    Public,
    RadioMeasurement,
    FastBssTransition,
    HighThroughput,
    SaQuery,
    ProtectedDualOfPublicAction,
    Wnm,
    UnprotectedWNM,
    Tdls,
    Mesh,
    Multihop,
    SelfProtected,
    Dmg,
    FastSessionTransfer,
    RobustAVStreaming,
    UnprotectedDMG,
    Vht,
    UnprotectedS1G,
    S1G,
    FlowControl,
    ControlResponseMCSNegotiation,
    Fils,
    Cdmg,
    Dmmg,
    Glk,
    VendorSpecificProtected,
    VendorSpecific,
    Error,
}

impl Action {
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded: Vec<u8> = Vec::new();

        // Encode the ManagementHeader
        encoded.extend(self.header.encode());

        // Encode the ActionCategory and action
        encoded.push(self.category.clone() as u8);
        encoded.push(self.action);

        // Encode StationInfo if necessary
        encoded.extend(self.station_info.encode());

        encoded
    }
}

impl From<u8> for ActionCategory {
    fn from(value: u8) -> Self {
        match value {
            0 => ActionCategory::SpectrumManagement,
            1 => ActionCategory::Qos,
            2 => ActionCategory::Reserved,
            3 => ActionCategory::BlockAck,
            4 => ActionCategory::Public,
            5 => ActionCategory::RadioMeasurement,
            6 => ActionCategory::FastBssTransition,
            7 => ActionCategory::HighThroughput,
            8 => ActionCategory::SaQuery,
            9 => ActionCategory::ProtectedDualOfPublicAction,
            10 => ActionCategory::Wnm,
            11 => ActionCategory::UnprotectedWNM,
            12 => ActionCategory::Tdls,
            13 => ActionCategory::Mesh,
            14 => ActionCategory::Multihop,
            15 => ActionCategory::SelfProtected,
            16 => ActionCategory::Dmg,
            17 => ActionCategory::Reserved,
            18 => ActionCategory::FastSessionTransfer,
            19 => ActionCategory::RobustAVStreaming,
            20 => ActionCategory::UnprotectedDMG,
            21 => ActionCategory::Vht,
            22 => ActionCategory::UnprotectedS1G,
            23 => ActionCategory::S1G,
            24 => ActionCategory::FlowControl,
            25 => ActionCategory::ControlResponseMCSNegotiation,
            26 => ActionCategory::Fils,
            27 => ActionCategory::Cdmg,
            28 => ActionCategory::Dmmg,
            29 => ActionCategory::Glk,
            30..=125 => ActionCategory::Reserved,
            126 => ActionCategory::VendorSpecificProtected,
            127 => ActionCategory::VendorSpecific,
            128..=255 => ActionCategory::Error,
        }
    }
}
