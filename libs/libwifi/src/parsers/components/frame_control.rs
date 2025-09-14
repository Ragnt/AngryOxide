use nom::sequence::tuple;
use nom::{bits, IResult};
use nom::{complete::take, error::Error};

use crate::frame::components::FrameControl;
use crate::frame_types::*;

/// Parse the frame control of a frame.
/// The format is the same for ALL frames, which makes this part quite unique.
pub fn parse_frame_control(input: &[u8]) -> IResult<&[u8], FrameControl> {
    let (remaining, (frame_subtype, frame_type, protocol_version, flags)) =
        bits::<_, (u8, u8, u8, u8), Error<(&[u8], usize)>, _, _>(tuple((
            take(4usize),
            take(2usize),
            take(2usize),
            take(8usize),
        )))(input)?;

    let frame_type = parse_frame_type(frame_type);

    // The next 4 bits are then used to determine the frame sub-type.
    // The sub-type depends on the current FrameType
    let frame_subtype = match frame_type {
        FrameType::Management => management_frame_subtype(frame_subtype),
        FrameType::Control => control_frame_subtype(frame_subtype),
        FrameType::Data => data_frame_subtype(frame_subtype),
        FrameType::Unknown => FrameSubType::Unhandled,
    };

    Ok((
        remaining,
        FrameControl {
            protocol_version,
            frame_type,
            frame_subtype,
            flags,
        },
    ))
}

/// Get the FrameType a two-bit integer (bits 3-4 of the payload).
fn parse_frame_type(byte: u8) -> FrameType {
    match byte {
        0 => FrameType::Management,
        1 => FrameType::Control,
        2 => FrameType::Data,
        _ => FrameType::Unknown,
    }
}

/// Get the FrameSubType from a 4-bit integer (bit 4-7) under
/// the assumption that this is a management frame.
fn management_frame_subtype(byte: u8) -> FrameSubType {
    match byte {
        0 => FrameSubType::AssociationRequest,
        1 => FrameSubType::AssociationResponse,
        2 => FrameSubType::ReassociationRequest,
        3 => FrameSubType::ReassociationResponse,
        4 => FrameSubType::ProbeRequest,
        5 => FrameSubType::ProbeResponse,
        6 => FrameSubType::TimingAdvertisement,
        7 => FrameSubType::Reserved,
        8 => FrameSubType::Beacon,
        9 => FrameSubType::Atim,
        10 => FrameSubType::Disassociation,
        11 => FrameSubType::Authentication,
        12 => FrameSubType::Deauthentication,
        13 => FrameSubType::Action,
        14 => FrameSubType::ActionNoAck,
        15 => FrameSubType::Reserved,
        _ => FrameSubType::Unhandled,
    }
}

/// Get the FrameSubType from a 4-bit integer (bit 4-7) under
/// the assumption that this is a control frame.
fn control_frame_subtype(byte: u8) -> FrameSubType {
    match byte {
        0 => FrameSubType::Reserved,
        1 => FrameSubType::Reserved,
        2 => FrameSubType::Trigger,
        3 => FrameSubType::Tack,
        4 => FrameSubType::BeamformingReportPoll,
        5 => FrameSubType::NdpAnnouncement,
        6 => FrameSubType::ControlFrameExtension,
        7 => FrameSubType::ControlWrapper,
        8 => FrameSubType::BlockAckRequest,
        9 => FrameSubType::BlockAck,
        10 => FrameSubType::PsPoll,
        11 => FrameSubType::Rts,
        12 => FrameSubType::Cts,
        13 => FrameSubType::Ack,
        14 => FrameSubType::CfEnd,
        15 => FrameSubType::CfEndCfAck,
        _ => FrameSubType::Unhandled,
    }
}

/// Get the FrameSubType from a 4-bit integer (bit 4-7) under
/// the assumption that this is a data frame.
fn data_frame_subtype(byte: u8) -> FrameSubType {
    match byte {
        0 => FrameSubType::Data,
        1 => FrameSubType::DataCfAck,
        2 => FrameSubType::DataCfPoll,
        3 => FrameSubType::DataCfAckCfPoll,
        4 => FrameSubType::NullData,
        5 => FrameSubType::CfAck,
        6 => FrameSubType::CfPoll,
        7 => FrameSubType::CfAckCfPoll,
        8 => FrameSubType::QosData,
        9 => FrameSubType::QosDataCfAck,
        10 => FrameSubType::QosDataCfPoll,
        11 => FrameSubType::QosDataCfAckCfPoll,
        12 => FrameSubType::QosNull,
        13 => FrameSubType::Reserved,
        14 => FrameSubType::QosCfPoll,
        15 => FrameSubType::QosCfAckCfPoll,
        _ => FrameSubType::Unhandled,
    }
}
