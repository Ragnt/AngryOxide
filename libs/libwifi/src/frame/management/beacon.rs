use libwifi_macros::AddressHeader;

use crate::frame::components::*;

#[derive(Clone, Debug, AddressHeader)]
pub struct Beacon {
    pub header: ManagementHeader,
    pub timestamp: u64,
    pub beacon_interval: u16,
    pub capability_info: u16,
    pub station_info: StationInfo,
}

impl Beacon {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Encode the ManagementHeader
        bytes.extend(self.header.encode());

        // Encode Timestamp
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());

        // Encode Beacon Interval
        bytes.extend_from_slice(&self.beacon_interval.to_le_bytes());

        // Encode Capability Info
        bytes.extend_from_slice(&self.capability_info.to_le_bytes());

        // Encode Station Info
        bytes.extend(self.station_info.encode());

        bytes
    }
}
