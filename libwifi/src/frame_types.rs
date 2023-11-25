use strum_macros::Display;

/// Enum with all frame types.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Display)]
pub enum FrameType {
    Management,
    Control,
    Data,
    Unknown,
}

pub enum ManagementSubTypes {
    AssociationRequest,
    AssociationResponse,
    ReassociationRequest,
    ReassociationResponse,
    ProbeRequest,
    ProbeResponse,
    TimingAdvertisement,
    Reserved,
    Beacon,
    Atim,
    Disassociation,
    Authentication,
    Deauthentication,
    Action,
    ActionNoAck,
}

/// Enum with all frame subtypes.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Display)]
pub enum FrameSubType {
    // Management subtypes
    AssociationRequest,
    AssociationResponse,
    ReassociationRequest,
    ReassociationResponse,
    ProbeRequest,
    ProbeResponse,
    TimingAdvertisement,
    Beacon,
    Atim,
    Disassociation,
    Authentication,
    Deauthentication,
    Action,
    ActionNoAck,

    // Control subtypes
    Trigger,
    Tack,
    BeamformingReportPoll,
    NdpAnnouncement,
    ControlFrameExtension,
    ControlWrapper,
    BlockAckRequest,
    BlockAck,
    PsPoll,
    Rts,
    Cts,
    Ack,
    CfEnd,
    CfEndCfAck,

    // Data subtypes
    Data,
    DataCfAck,
    DataCfPoll,
    DataCfAckCfPoll,
    NullData,
    CfAck,
    CfPoll,
    CfAckCfPoll,
    QosData,
    QosDataCfAck,
    QosDataCfPoll,
    QosDataCfAckCfPoll,
    QosNull,
    QosCfPoll,
    QosCfAckCfPoll,

    // Special subtypes
    Unhandled,
    Reserved,
}

impl FrameSubType {
    pub fn is_qos(&self) -> bool {
        matches!(
            self,
            FrameSubType::QosData
                | FrameSubType::QosDataCfAck
                | FrameSubType::QosDataCfPoll
                | FrameSubType::QosDataCfAckCfPoll
                | FrameSubType::QosNull
                | FrameSubType::QosCfPoll
                | FrameSubType::QosCfAckCfPoll,
        )
    }

    pub fn to_bytes(&self) -> u8 {
        match self {
            FrameSubType::AssociationRequest => 0,
            FrameSubType::AssociationResponse => 1,
            FrameSubType::ReassociationRequest => 2,
            FrameSubType::ReassociationResponse => 3,
            FrameSubType::ProbeRequest => 4,
            FrameSubType::ProbeResponse => 5,
            FrameSubType::TimingAdvertisement => 6,
            FrameSubType::Beacon => 8,
            FrameSubType::Atim => 9,
            FrameSubType::Disassociation => 10,
            FrameSubType::Authentication => 11,
            FrameSubType::Deauthentication => 12,
            FrameSubType::Action => 13,
            FrameSubType::ActionNoAck => 14,
            FrameSubType::Trigger => 2,
            FrameSubType::Tack => 3,
            FrameSubType::BeamformingReportPoll => 4,
            FrameSubType::NdpAnnouncement => 5,
            FrameSubType::ControlFrameExtension => 6,
            FrameSubType::ControlWrapper => 7,
            FrameSubType::BlockAckRequest => 8,
            FrameSubType::BlockAck => 9,
            FrameSubType::PsPoll => 10,
            FrameSubType::Rts => 11,
            FrameSubType::Cts => 12,
            FrameSubType::Ack => 13,
            FrameSubType::CfEnd => 14,
            FrameSubType::CfEndCfAck => 15,
            FrameSubType::Data => 0,
            FrameSubType::DataCfAck => 1,
            FrameSubType::DataCfPoll => 2,
            FrameSubType::DataCfAckCfPoll => 3,
            FrameSubType::NullData => 4,
            FrameSubType::CfAck => 5,
            FrameSubType::CfPoll => 6,
            FrameSubType::CfAckCfPoll => 7,
            FrameSubType::QosData => 8,
            FrameSubType::QosDataCfAck => 9,
            FrameSubType::QosDataCfPoll => 10,
            FrameSubType::QosDataCfAckCfPoll => 11,
            FrameSubType::QosNull => 12,
            FrameSubType::QosCfPoll => 14,
            FrameSubType::QosCfAckCfPoll => 15,
            _ => 255,
        }
    }
}
