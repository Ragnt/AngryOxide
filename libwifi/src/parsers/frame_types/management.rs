use nom::bytes::complete::take;
use nom::number::complete::{le_u16, le_u64};

use nom::sequence::tuple;

use crate::error::Error;
use crate::frame::components::FrameControl;
use crate::frame::*;
use crate::parsers::{parse_management_header, parse_station_info};

/// Parse an [AssociationRequest] frame.
///
/// The general structure is:
/// - ManagementHeader
/// - Beacon interval
/// - Capability info
/// - Dynamic fields
pub fn parse_association_request(
    frame_control: FrameControl,
    input: &[u8],
) -> Result<Frame, Error> {
    let (input, header) = parse_management_header(frame_control, input)?;
    let (_, (beacon_interval, capability_info, station_info)) =
        tuple((le_u16, le_u16, parse_station_info))(input)?;

    Ok(Frame::AssociationRequest(AssociationRequest {
        header,
        beacon_interval,
        capability_info,
        station_info,
    }))
}

/// Parse an [Authentication] frame.
///
/// The general structure is:
/// - ManagementHeader
/// - Authentication Algorithm Number
/// - Authentication Transaction Sequence Number
/// - Status Code
/// - Challenge Text (optional, dynamic length)
pub fn parse_authentication_frame(
    frame_control: FrameControl,
    input: &[u8],
) -> Result<Frame, Error> {
    let (input, header) = parse_management_header(frame_control, input)?;

    // Parse the fixed fields
    let (input, auth_algorithm) = le_u16(input)?;
    let (input, auth_seq) = le_u16(input)?;
    let (input, status_code) = le_u16(input)?;

    // Parse the optional challenge text, if present
    let (input, challenge_text) = if input.is_empty() {
        (input, None)
    } else {
        let (input, length) = le_u16(input)?;
        let (input, text) = take(length)(input)?;
        (input, Some(text.to_vec()))
    };

    Ok(Frame::Authentication(Authentication {
        header,
        auth_algorithm,
        auth_seq,
        status_code,
        challenge_text,
    }))
}

/// Parse a [Deauthentication] frame.
///
/// The general structure is:
/// - ManagementHeader
/// - Reason Code
pub fn parse_deauthentication_frame(
    frame_control: FrameControl,
    input: &[u8],
) -> Result<Frame, Error> {
    let (input, header) = parse_management_header(frame_control, input)?;

    // Parse the reason code
    let (input, reason_code) = le_u16(input)?;

    Ok(Frame::Deauthentication(Deauthentication {
        header,
        reason_code,
    }))
}

/// Parse an [AssociationResponse] frame.
///
/// The general structure is:
/// - ManagementHeader
/// - Capability info
/// - Status code
/// - Association id
/// - Dynamic fields
pub fn parse_association_response(
    frame_control: FrameControl,
    input: &[u8],
) -> Result<Frame, Error> {
    let (input, header) = parse_management_header(frame_control, input)?;
    let (_, (capability_info, status_code, association_id, station_info)) =
        tuple((le_u16, le_u16, le_u16, parse_station_info))(input)?;

    Ok(Frame::AssociationResponse(AssociationResponse {
        header,
        capability_info,
        status_code,
        association_id,
        station_info,
    }))
}

/// Parse a [Beacon] frame.
///
/// The general structure is:
/// - ManagementHeader
/// - Beacon interval
/// - Capability info
/// - Dynamic fields
pub fn parse_beacon(frame_control: FrameControl, input: &[u8]) -> Result<Frame, Error> {
    let (input, header) = parse_management_header(frame_control, input)?;
    let (_, (timestamp, beacon_interval, capability_info, station_info)) =
        tuple((le_u64, le_u16, le_u16, parse_station_info))(input)?;

    Ok(Frame::Beacon(Beacon {
        header,
        timestamp,
        beacon_interval,
        capability_info,
        station_info,
    }))
}

/// Parse a [ProbeRequest] frame.
///
/// The general structure is:
/// - ManagementHeader
/// - Dynamic fields
pub fn parse_probe_request(frame_control: FrameControl, input: &[u8]) -> Result<Frame, Error> {
    let (input, header) = parse_management_header(frame_control, input)?;
    let (_, station_info) = parse_station_info(input)?;

    Ok(Frame::ProbeRequest(ProbeRequest {
        header,
        station_info,
    }))
}

/// Parse a [ProbeResponse] frame.
///
/// The general structure is:
/// - ManagementHeader
/// - Beacon interval
/// - Capability info
/// - Dynamic fields
pub fn parse_probe_response(frame_control: FrameControl, input: &[u8]) -> Result<Frame, Error> {
    let (input, header) = parse_management_header(frame_control, input)?;
    let (_, (timestamp, beacon_interval, capability_info, station_info)) =
        tuple((le_u64, le_u16, le_u16, parse_station_info))(input)?;

    Ok(Frame::ProbeResponse(ProbeResponse {
        header,
        timestamp,
        beacon_interval,
        capability_info,
        station_info,
    }))
}
