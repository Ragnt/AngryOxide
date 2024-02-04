/// Libwifi's own [Error](error::Error) implementation
pub mod error;
/// The [Frame](frame::Frame) enum and all frame structs.
pub mod frame;
/// Enums representing frame types and frame subtypes.
mod frame_types;
/// [nom] parsers for internal usage.
pub mod parsers;
/// All traits used or provided by this library.
mod traits;

use crate::error::Error;
use crate::parsers::*;

// Re-exports for user convenience
pub use crate::frame::Frame;
pub use crate::frame_types::*;
pub use crate::traits::*;

use crc::{Crc, CRC_32_ISO_HDLC};

// CRC algorithm for FCS calculation
const CRC_32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

/// Parse IEE 802.11 frames from raw bytes.
///
pub fn parse_frame(input: &[u8], fcs_included: bool) -> Result<Frame, Error> {
    if fcs_included {
        if input.len() < 4 {
            return Err(Error::Incomplete("Incomplete".to_string()));
        }

        // Split the input into frame data and FCS
        let (frame_data, fcs_bytes) = input.split_at(input.len() - 4);

        // Calculate the CRC over the frame data
        let crc = CRC_32.checksum(frame_data);

        // Convert the last 4 bytes (FCS) to a u32 -- this needs to be little endian I guess?
        let fcs = u32::from_le_bytes([fcs_bytes[0], fcs_bytes[1], fcs_bytes[2], fcs_bytes[3]]);

        // Verify the FCS
        if crc != fcs {
            return Err(Error::Incomplete(format!(
                "(FCS) mismatch {:02x} {:02x}",
                crc, fcs
            )));
        }
    }

    let (input, frame_control) = parse_frame_control(input)?;

    // Check which kind of frame sub-type we got
    match frame_control.frame_subtype {
        // Management
        FrameSubType::Beacon => parse_beacon(frame_control, input),
        FrameSubType::ProbeRequest => parse_probe_request(frame_control, input),
        FrameSubType::ProbeResponse => parse_probe_response(frame_control, input),
        FrameSubType::AssociationRequest => parse_association_request(frame_control, input),
        FrameSubType::AssociationResponse => parse_association_response(frame_control, input),
        FrameSubType::ReassociationRequest => parse_reassociation_request(frame_control, input),
        FrameSubType::ReassociationResponse => parse_reassociation_response(frame_control, input),
        FrameSubType::Authentication => parse_authentication_frame(frame_control, input),
        FrameSubType::Deauthentication => parse_deauthentication_frame(frame_control, input),
        FrameSubType::Action => parse_action(frame_control, input),

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
        FrameSubType::DataCfAck => parse_data_cf_ack(frame_control, input),
        FrameSubType::DataCfPoll => parse_data_cf_poll(frame_control, input),
        FrameSubType::DataCfAckCfPoll => parse_data_cf_ack_cf_poll(frame_control, input),
        FrameSubType::CfAck => parse_cf_ack(frame_control, input),
        FrameSubType::CfPoll => parse_cf_poll(frame_control, input),
        FrameSubType::CfAckCfPoll => parse_cf_ack_cf_poll(frame_control, input),
        FrameSubType::QosDataCfAck => parse_qos_data_cf_ack(frame_control, input),
        FrameSubType::QosDataCfPoll => parse_qos_data_cf_poll(frame_control, input),
        FrameSubType::QosDataCfAckCfPoll => parse_qos_data_cf_ack_cf_poll(frame_control, input),
        FrameSubType::QosCfPoll => parse_qos_cf_poll(frame_control, input),
        FrameSubType::QosCfAckCfPoll => parse_qos_cf_ack_cf_poll(frame_control, input),
        _ => Err(Error::UnhandledFrameSubtype(frame_control, input.to_vec())),
    }
}

#[cfg(doctest)]
doc_comment::doctest!("../../README.md");
