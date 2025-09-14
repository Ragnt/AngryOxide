use nom::bits;
use nom::bytes::complete::take;
use nom::complete::take as bit_take;
use nom::error::Error as NomError;
use nom::number::complete::le_u64;
use nom::sequence::tuple;

use crate::frame::components::{FrameControl, SequenceControl};
use crate::frame::*;
use crate::parsers::{clone_slice, flag, parse_mac};
use crate::{error::Error, parsers::parse_sequence_control};

/// Parse a [Rts] frame.
///
/// The general structure is:
/// - FrameControl
/// - Duration
/// - Source
/// - Destination
pub fn parse_rts(frame_control: FrameControl, input: &[u8]) -> Result<Frame, Error> {
    let (_, (duration, destination, source)) = tuple((take(2usize), parse_mac, parse_mac))(input)?;

    Ok(Frame::Rts(Rts {
        frame_control,
        duration: clone_slice::<2>(duration),
        source,
        destination,
    }))
}

/// Parse a [Cts] frame.
///
/// The general structure is:
/// - FrameControl
/// - Duration
/// - Destination
pub fn parse_cts(frame_control: FrameControl, input: &[u8]) -> Result<Frame, Error> {
    let (_, (duration, destination)) = tuple((take(2usize), parse_mac))(input)?;

    Ok(Frame::Cts(Cts {
        frame_control,
        duration: clone_slice::<2>(duration),
        destination,
    }))
}

/// Parse an [Ack] frame.
///
/// The general structure is:
/// - FrameControl
/// - Duration
/// - Destination
pub fn parse_ack(frame_control: FrameControl, input: &[u8]) -> Result<Frame, Error> {
    let (_, (duration, destination)) = tuple((take(2usize), parse_mac))(input)?;

    Ok(Frame::Ack(Ack {
        frame_control,
        duration: clone_slice::<2>(duration),
        destination,
    }))
}

/// Parse a [BlockAckRequest] frame.
///
/// Check the inline docs and the docs of [BlockAckRequest] for more information.
/// This is a rather complicated one, but the docs should make things more clear.
pub fn parse_block_ack_request(frame_control: FrameControl, input: &[u8]) -> Result<Frame, Error> {
    let (mut request_information, (duration, destination, source, bar_control)) =
        tuple((take(2usize), parse_mac, parse_mac, take(2usize)))(input)?;

    let (_, (policy, multi_tid, compressed_bitmap, _, tid_info)) =
        bits::<_, (bool, bool, bool, u16, u8), NomError<(&[u8], usize)>, _, _>(tuple((
            flag,
            flag,
            flag,
            // These are the reserved
            bit_take(9usize),
            bit_take(4usize),
        )))(bar_control)?;

    // The TID_INFO and the BAR information field work in conjunction to provide information on
    // the number of TIDs in let number = ((vector[0] as u16) << 8) | vector[1] as u16;the request and starting sequence control and per TID info in the
    // case of Multi-TID aggregation.
    let mode = match (multi_tid, compressed_bitmap) {
        (true, true) => {
            // The frame is a Multi-TID BlockAckRequest.
            // This means, the TID_INFO field indicates the number of packets/TID present in the
            // block ACK request **+ 1**.
            //
            // For instance, if TID_INFO is 2 then 3 TIDs are present.
            BlockAckMode::MultiTidBlockAck
        }
        (true, false) => {
            return Err(Error::UnhandledProtocol(
                "BlockAckMode::Reserved in BlockAck parser.".to_string(),
            ))
        }
        (false, false) => {
            // In normal ACK mode, the tid_info field also contains the TID for
            // which the block ACK request is sent out.
            // The BAR information field contains the starting sequence number of frame from
            // which the block Ack is desired
            BlockAckMode::BasicBlockAck
        }
        (false, true) => {
            // The same as BasicBlockAck, but we request a compressed bitmap.
            BlockAckMode::CompressedBlockAck
        }
    };

    // This is a vector of all requested TIDs
    // It's a tuple of (TID, starting sequence control)
    let mut requested_tids: Vec<(u8, SequenceControl)> = Vec::new();

    match mode {
        BlockAckMode::MultiTidBlockAck => {
            let mut inner_tid_info: &[u8];
            let mut sequence_control: SequenceControl;

            // Multi TID mode, we expect tid_info + 1 elements in the
            for _ in 0..tid_info + 1 {
                // Each requested is split into two segments
                // - 2 bytes `tid_info`:
                //      `tid_info` is split into 12 bits reserved space and 4 bits TID value
                // - 2 bytes squence control
                (request_information, (inner_tid_info, sequence_control)) =
                    tuple((take(2usize), parse_sequence_control))(request_information)?;

                // Extract the 4 bits TID
                let (_, (_, tid)) = bits::<_, (u16, u8), NomError<(&[u8], usize)>, _, _>(tuple((
                    bit_take(12usize),
                    bit_take(4usize),
                )))(inner_tid_info)?;

                requested_tids.push((tid, sequence_control));
            }
        }

        BlockAckMode::CompressedBlockAck | BlockAckMode::BasicBlockAck => {
            // In non multi-tid mode, the bar_information only contains the sequence_control of the requested TID.
            let (_, sequence_control) = parse_sequence_control(request_information)?;
            requested_tids.push((tid_info, sequence_control));
        }
    }

    Ok(Frame::BlockAckRequest(BlockAckRequest {
        frame_control,
        duration: clone_slice::<2>(duration),
        source,
        destination,
        policy,
        mode,
        requested_tids,
    }))
}

/// Parse a [BlockAck] frame.
///
/// Check the inline docs and the docs of [BlockAck] for more information.
/// This is a rather complicated one, but the docs should make things more clear.
pub fn parse_block_ack(frame_control: FrameControl, input: &[u8]) -> Result<Frame, Error> {
    let (mut ack_information, (duration, destination, source, bar_control)) =
        tuple((take(2usize), parse_mac, parse_mac, take(2usize)))(input)?;

    let (_, (policy, multi_tid, compressed_bitmap, _, tid_info)) =
        bits::<_, (bool, bool, bool, u16, u8), NomError<(&[u8], usize)>, _, _>(tuple((
            flag,
            flag,
            flag,
            // These are the reserved
            bit_take(9usize),
            bit_take(4usize),
        )))(bar_control)?;

    // The TID_INFO and the BAR information field work in conjunction to provide information on
    // the number of TIDs in let number = ((vector[0] as u16) << 8) | vector[1] as u16;the request and starting sequence control and per TID info in the
    // case of Multi-TID aggregation.
    let mode = match (multi_tid, compressed_bitmap) {
        (true, true) => {
            // The frame is a Multi-TID BlockAck.
            // This means, the TID_INFO field indicates the number of packets/TID present in the
            // block ACK request **+ 1**.
            //
            // For instance, if TID_INFO is 2 then 3 TIDs are present.
            BlockAckMode::MultiTidBlockAck
        }
        (true, false) => {
            return Err(Error::UnhandledProtocol(
                "BlockAckMode::Reserved in BlockAck parser.".to_string(),
            ))
        }
        (false, false) => {
            // In normal ACK mode, the tid_info field also contains the TID for
            // which the block ACK request has been sent out.
            //
            // We'll later parse the 128 bitmap.
            BlockAckMode::BasicBlockAck
        }
        (false, true) => {
            // The same as BasicBlockAck, but we request a compressed bitmap.
            BlockAckMode::CompressedBlockAck
        }
    };

    // This is a vector of all requested TIDs
    // It's a tuple of (TID, starting sequence control)

    let acks = match mode {
        BlockAckMode::MultiTidBlockAck => {
            let mut inner_tid_info: &[u8];
            let mut sequence_control: SequenceControl;
            let mut bitmap: u64;

            // Vector with all acknowledged TIDs, their sequence control and bitmap.
            let mut acks: Vec<(u8, SequenceControl, u64)> = Vec::new();

            // Multi TID mode, we expect tid_info + 1 elements in the
            for _ in 0..tid_info + 1 {
                // Each requested is split into three segments
                // - 2 bytes `tid_info`:
                //      `tid_info` is split into 12 bits reserved space and 4 bits TID value
                // - 2 bytes squence control
                // - 8 bytes BlockAck bitmap
                (ack_information, (inner_tid_info, sequence_control, bitmap)) =
                    tuple((take(2usize), parse_sequence_control, le_u64))(ack_information)?;

                // Extract the 4 bits TID
                let (_, (_, tid)) = bits::<_, (u16, u8), NomError<(&[u8], usize)>, _, _>(tuple((
                    bit_take(12usize),
                    bit_take(4usize),
                )))(inner_tid_info)?;

                acks.push((tid, sequence_control, bitmap));
            }
            BlockAckInfo::Compressed(acks)
        }
        BlockAckMode::CompressedBlockAck => {
            // In normal Non-multi-TID mode, `ack_information` only consists of a sequence control
            // and the bitmap. `tid_info` is the actual id of the TID that's acknowledged.
            let mut acks: Vec<(u8, SequenceControl, u64)> = Vec::new();

            let (_, (sequence_control, bitmap)) =
                tuple((parse_sequence_control, le_u64))(ack_information)?;
            acks.push((tid_info, sequence_control, bitmap));
            BlockAckInfo::Compressed(acks)
        }
        BlockAckMode::BasicBlockAck => {
            // In non multi-tid mode, the bar_information only contains the sequence_control of the requested TID.
            //
            let (_, (sequence_control, bitmap)) =
                tuple((parse_sequence_control, take(128usize)))(ack_information)?;

            BlockAckInfo::Basic((tid_info, sequence_control, clone_slice::<128>(bitmap)))
        }
    };

    Ok(Frame::BlockAck(BlockAck {
        frame_control,
        duration: clone_slice::<2>(duration),
        source,
        destination,
        policy,
        mode,
        acks,
    }))
}
