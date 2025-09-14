use libwifi_macros::AddressHeader;

use crate::frame::components::*;

use super::DeauthenticationReason;

#[derive(Clone, Debug, AddressHeader)]
pub struct AssociationRequest {
    pub header: ManagementHeader,
    pub beacon_interval: u16,
    pub capability_info: u16,
    pub station_info: StationInfo,
}

impl AssociationRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Encode the ManagementHeader
        bytes.extend(self.header.encode());

        // Encode Capability Info
        bytes.extend_from_slice(&self.capability_info.to_le_bytes());

        // Encode Beacon Interval
        bytes.extend_from_slice(&self.beacon_interval.to_le_bytes());

        // Encode Station Info
        bytes.extend(self.station_info.encode());

        bytes
    }
}

#[derive(Clone, Debug, AddressHeader)]
pub struct AssociationResponse {
    pub header: ManagementHeader,
    pub capability_info: u16,
    pub status_code: u16,
    pub association_id: u16,
    pub station_info: StationInfo,
}

impl AssociationResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Encode the ManagementHeader
        bytes.extend(self.header.encode());

        // Encode Capability Info
        bytes.extend_from_slice(&self.capability_info.to_le_bytes());

        // Encode Status Code
        bytes.extend_from_slice(&self.status_code.to_le_bytes());

        // Encode Association ID
        bytes.extend_from_slice(&self.association_id.to_le_bytes());

        // Encode Station Info
        bytes.extend(self.station_info.encode());

        bytes
    }
}

#[derive(Clone, Debug, AddressHeader)]
pub struct ReassociationRequest {
    pub header: ManagementHeader,
    pub capability_info: u16,
    pub listen_interval: u16,
    pub current_ap_address: MacAddress, // MAC address of the current AP
    pub station_info: StationInfo,
}

impl ReassociationRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Encode the ManagementHeader
        bytes.extend(self.header.encode());

        // Encode Capability Info
        bytes.extend_from_slice(&self.capability_info.to_le_bytes());

        // Encode Listen Interval
        bytes.extend_from_slice(&self.listen_interval.to_le_bytes());

        // Encode Current AP Address
        bytes.extend_from_slice(&self.current_ap_address.encode());

        // Encode Station Info
        bytes.extend(self.station_info.encode());

        bytes
    }
}

#[derive(Clone, Debug, AddressHeader)]
pub struct ReassociationResponse {
    pub header: ManagementHeader,
    pub capability_info: u16,
    pub status_code: u16,
    pub association_id: u16,
    pub station_info: StationInfo,
}

impl ReassociationResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Encode the ManagementHeader
        bytes.extend(self.header.encode());

        // Encode Capability Info
        bytes.extend_from_slice(&self.capability_info.to_le_bytes());

        // Encode Status Code
        bytes.extend_from_slice(&self.status_code.to_le_bytes());

        // Encode Association ID
        bytes.extend_from_slice(&self.association_id.to_le_bytes());

        bytes
    }
}

#[derive(Clone, Debug, AddressHeader)]
pub struct Disassociation {
    pub header: ManagementHeader,
    pub reason_code: DeauthenticationReason,
}

impl Disassociation {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Encode the ManagementHeader
        bytes.extend(self.header.encode());

        // Encode Reason Code
        bytes.extend_from_slice(&(self.reason_code.clone() as u16).to_ne_bytes());

        bytes
    }
}
