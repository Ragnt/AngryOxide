use libwifi_macros::AddressHeader;

use crate::frame::components::*;

#[derive(Clone, Debug, AddressHeader)]
pub struct ProbeRequest {
    pub header: ManagementHeader,
    pub station_info: StationInfo,
}

#[derive(Clone, Debug, AddressHeader)]
pub struct ProbeResponse {
    pub header: ManagementHeader,
    pub timestamp: u64,
    pub beacon_interval: u16,
    pub capability_info: u16,
    pub station_info: StationInfo,
}
