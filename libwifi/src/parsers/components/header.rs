use nom::bytes::complete::take;
use nom::combinator::opt;
use nom::sequence::tuple;

use super::{clone_slice, parse_mac, parse_sequence_control};
use crate::error::Error;
use crate::frame::components::{DataHeader, FrameControl, ManagementHeader};

/// Parse and return the [ManagementHeader] from a given payload.
pub fn parse_management_header(
    frame_control: FrameControl,
    input: &[u8],
) -> Result<(&[u8], ManagementHeader), Error> {
    let (remaining, (duration, address_1, address_2, address_3, sequence_control)) = tuple((
        take(2usize),
        parse_mac,
        parse_mac,
        parse_mac,
        parse_sequence_control,
    ))(input)?;

    let duration = clone_slice::<2>(duration);

    Ok((
        remaining,
        ManagementHeader {
            frame_control,
            duration,
            address_1,
            address_2,
            address_3,
            sequence_control,
        },
    ))
}

/// Parse and return the [DataHeader] from a given payload.
pub fn parse_data_header(
    frame_control: FrameControl,
    input: &[u8],
) -> Result<(&[u8], DataHeader), Error> {
    let (mut remaining, (duration, address_1, address_2, address_3, sequence_control)) =
        tuple((
            take(2usize),
            parse_mac,
            parse_mac,
            parse_mac,
            parse_sequence_control,
        ))(input)?;

    let duration = clone_slice::<2>(duration);

    // The forth address only exists if both `from_ds` and `to_ds` is set.
    let mut address_4 = None;
    if frame_control.to_ds() && frame_control.from_ds() {
        (remaining, address_4) = opt(parse_mac)(remaining)?;
    };

    // If this is a Qos frame subtype, we go ahead and parse any Qos related info.
    let mut qos = None;
    if frame_control.frame_subtype.is_qos() {
        let (_remaining, qos_bytes) = take(2usize)(remaining)?;
        qos = Some(clone_slice::<2>(qos_bytes));
        remaining = _remaining;
    }

    Ok((
        remaining,
        DataHeader {
            frame_control,
            duration,
            address_1,
            address_2,
            address_3,
            sequence_control,
            address_4,
            qos,
        },
    ))
}
