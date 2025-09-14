use nom::bytes::complete::take;
use nom::number::complete::{le_u16, le_u64, le_u8};

use nom::sequence::tuple;

use crate::error::Error;
use crate::frame::components::FrameControl;
use crate::frame::*;
use crate::parsers::{parse_mac, parse_management_header, parse_station_info};

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

    let mut challenge_text = None;
    let mut station_info = None;

    if auth_algorithm == 1 && (auth_seq == 2 || auth_seq == 3) {
        // Parse the optional challenge text
        if !input.is_empty() {
            let (input, length) = le_u16(input)?;
            let (_input, text) = take(length)(input)?;
            challenge_text = Some(text.to_vec());
        };
    } else {
        // Parse station info (extended capabilities) if present
        if !input.is_empty() {
            if let Ok((_input, info)) = parse_station_info(input) {
                station_info = Some(info);
            }
        }
    }

    Ok(Frame::Authentication(Authentication {
        header,
        auth_algorithm,
        auth_seq,
        status_code,
        challenge_text,
        station_info,
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
    let (_, reason_code) = le_u16(input)?;

    Ok(Frame::Deauthentication(Deauthentication {
        header,
        reason_code: DeauthenticationReason::from_code(reason_code),
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

/// Parse a [ReassociationRequest] frame.
///
/// The general structure is:
/// - ManagementHeader
/// - Capability info
/// - Listen interval
/// - Current AP address (MAC address)
/// - Dynamic fields (like StationInfo)
pub fn parse_reassociation_request(
    frame_control: FrameControl,
    input: &[u8],
) -> Result<Frame, Error> {
    let (input, header) = parse_management_header(frame_control, input)?;
    let (input, (capability_info, listen_interval)) = tuple((le_u16, le_u16))(input)?;

    let (input, current_ap_address) = parse_mac(input)?;
    let (_, station_info) = parse_station_info(input)?;

    Ok(Frame::ReassociationRequest(ReassociationRequest {
        header,
        capability_info,
        listen_interval,
        current_ap_address,
        station_info,
    }))
}

/// Parse a [ReassociationResponse] frame.
///
/// The general structure is:
/// - ManagementHeader
/// - Capability info
/// - Status code
/// - Association id
pub fn parse_reassociation_response(
    frame_control: FrameControl,
    input: &[u8],
) -> Result<Frame, Error> {
    let (input, header) = parse_management_header(frame_control, input)?;
    let (_, (capability_info, status_code, association_id)) =
        tuple((le_u16, le_u16, le_u16))(input)?;
    let (_, station_info) = parse_station_info(input)?;

    Ok(Frame::ReassociationResponse(ReassociationResponse {
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

/// Parse an [Action] frame.
///
/// The general structure is:
/// - ManagementHeader
/// - Category (indicating the type of action, e.g., spectrum management, QoS)
/// - Action (specific action within the category)
/// - Dynamic fields (vary depending on the category and action)
pub fn parse_action(frame_control: FrameControl, input: &[u8]) -> Result<Frame, Error> {
    let (input, header) = parse_management_header(frame_control, input)?;

    // Parsing the category field (1 byte)
    let (input, category) = le_u8(input)?;

    // Parsing the action field (1 byte)
    let (input, action) = le_u8(input)?;

    // Parsing the dynamic fields (depends on category and action)
    let (_, station_info) = parse_station_info(input)?;

    // Assuming `StationInfo` is part of dynamic fields and its parsing
    // is handled inside `parse_dynamic_fields`
    // ...

    Ok(Frame::Action(Action {
        header,
        category: category.into(), // Convert to enum variant if needed
        action,                    // Convert to enum variant if needed
        station_info,              // Assuming this comes from dynamic fields
    }))
}
