/// Libwifi's own [Error](error::Error) implementation
pub mod error;
/// The [Frame](frame::Frame) enum and all frame structs.
pub mod frame;
/// Enums representing frame types and frame subtypes.
mod frame_types;
/// [nom] parsers for internal usage.
mod parsers;
/// All traits used or provided by this library.
mod traits;

use crate::error::Error;
use crate::parsers::*;

// Re-exports for user convenience
pub use crate::frame::Frame;
pub use crate::frame_types::*;
pub use crate::traits::*;

/// Parse IEE 802.11 frames from raw bytes.
///
/// This function doesn't do FCS checks. These need to be done separately.
pub fn parse_frame(input: &[u8]) -> Result<Frame, Error> {
    let (input, frame_control) = parse_frame_control(input)?;
    //println!(
    //    "Type/Subtype: {:?}, {:?}",
    //    frame_control.frame_type, frame_control.frame_subtype
    //);
    //println!("Payload bytes: {:?}", &input);

    // Check which kind of frame sub-type we got
    match frame_control.frame_subtype {
        // Management
        FrameSubType::Beacon => parse_beacon(frame_control, input),
        FrameSubType::ProbeRequest => parse_probe_request(frame_control, input),
        FrameSubType::ProbeResponse => parse_probe_response(frame_control, input),
        FrameSubType::AssociationRequest => parse_association_request(frame_control, input),
        FrameSubType::AssociationResponse => parse_association_response(frame_control, input),
        FrameSubType::Authentication => parse_authentication_frame(frame_control, input),
        FrameSubType::Deauthentication => parse_deauthentication_frame(frame_control, input),

        // Control
        FrameSubType::Rts => parse_rts(frame_control, input),
        FrameSubType::Cts => parse_cts(frame_control, input),
        FrameSubType::Ack => parse_ack(frame_control, input),
        FrameSubType::BlockAckRequest => parse_block_ack_request(frame_control, input),
        FrameSubType::BlockAck => parse_block_ack(frame_control, input),

        // Data
        FrameSubType::Data => parse_data(frame_control, input),
        FrameSubType::NullData => parse_null_data(frame_control, input),
        FrameSubType::QosData => parse_qos_data(frame_control, input),
        FrameSubType::QosNull => parse_qos_null(frame_control, input),
        _ => Err(Error::UnhandledFrameSubtype(frame_control, input.to_vec())),
    }
}

#[cfg(doctest)]
doc_comment::doctest!("../../README.md");
