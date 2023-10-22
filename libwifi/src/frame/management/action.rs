use libwifi_macros::AddressHeader;

use crate::frame::components::*;

enum ActionCategory {
    SpectrumManagement,
    Qos,
    Dls,
    BlockAck,
    Public,
    RadioMeasurement,
    FastBssTransition,
    HighThroughput,
    SaQuery,
    ProtectedDualOfPublicAction,
    Reserved,
    VendorSpecificProtected,
    VendorSpecific,
    Error,
}

enum Action {

}

#[derive(Clone, Debug, AddressHeader)]
pub struct Action {
    pub header: ManagementHeader,
    pub category: ,
    pub action: ,
    pub station_info: StationInfo,
}
