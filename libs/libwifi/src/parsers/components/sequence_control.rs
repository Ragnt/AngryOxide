use nom::complete::take;
use nom::error::Error;
use nom::sequence::tuple;
use nom::{bits, IResult};

use crate::frame::components::SequenceControl;

/// Parse and return the [ManagementHeader] from a given payload.
pub fn parse_sequence_control(input: &[u8]) -> IResult<&[u8], SequenceControl> {
    let (remaining, (fragment_number, sequence_number)) =
        bits::<_, (u8, u16), Error<(&[u8], usize)>, _, _>(tuple((take(4usize), take(12usize))))(
            input,
        )?;

    Ok((
        remaining,
        SequenceControl {
            fragment_number,
            sequence_number,
        },
    ))
}
