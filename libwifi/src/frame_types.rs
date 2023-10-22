use strum_macros::Display;

/// Enum with all frame types.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Display)]
pub enum FrameType {
    Management,
    Control,
    Data,
    Unknown,
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
    Reserved,
    Unhandled,
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
}
