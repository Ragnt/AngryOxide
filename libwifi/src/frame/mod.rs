use enum_dispatch::enum_dispatch;

/// Contains structs representing recurring sets of structured data.
/// For instance, MAC-Addresses, default headers, etc.
pub mod components;

/// Control frame structs
mod control;
/// Data frames structs
mod data;
/// Management frame structs
mod management;

pub use control::*;
pub use data::*;
pub use management::*;

#[enum_dispatch(Addresses)]
#[derive(Clone, Debug)]
/// This represents all currently supported payloads for frame subtypes.
/// Each variant is represented by its own struct.
///
/// The structs are organized by their frame type in submodules.
pub enum Frame {
    // Management frames
    Beacon(Beacon),
    ProbeRequest(ProbeRequest),
    ProbeResponse(ProbeResponse),
    AssociationRequest(AssociationRequest),
    AssociationResponse(AssociationResponse),
    ReassociationRequest(ReassociationRequest),
    ReassociationResponse(ReassociationResponse),
    Action(Action),

    // Authentication
    Authentication(Authentication),
    Deauthentication(Deauthentication),

    // Control Frames
    Rts(Rts),
    Cts(Cts),
    Ack(Ack),
    BlockAckRequest(BlockAckRequest),
    BlockAck(BlockAck),

    // Data Frames
    Data(Data),
    QosData(QosData),
    DataCfAck(DataCfAck),
    DataCfPoll(DataCfPoll),
    DataCfAckCfPoll(DataCfAckCfPoll),
    CfAck(CfAck),
    CfPoll(CfPoll),
    CfAckCfPoll(CfAckCfPoll),
    QosDataCfAck(QosDataCfAck),
    QosDataCfPoll(QosDataCfPoll),
    QosDataCfAckCfPoll(QosDataCfAckCfPoll),
    // No eapol
    QosCfPoll(QosCfPoll),
    QosCfAckCfPoll(QosCfAckCfPoll),
    QosNull(QosNull),
    NullData(NullData),
}
