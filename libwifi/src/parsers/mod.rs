use nom::{IResult, Needed};

mod components;
mod frame_types;

pub use components::*;
pub use frame_types::*;

#[inline]
/// Mini helper to check, whether a bit is set or not.
fn flag_is_set(data: u8, bit: usize) -> bool {
    if bit == 0 {
        let mask = 1;
        (data & mask) > 0
    } else {
        let mask = 1 << bit;
        (data & mask) > 0
    }
}

pub(self) fn flag((input, bit_offset): (&[u8], usize)) -> IResult<(&[u8], usize), bool> {
    if input.is_empty() {
        return Err(nom::Err::Incomplete(Needed::new(1)));
    }
    let flag = flag_is_set(input[0], bit_offset);
    if bit_offset == 7 {
        return Ok(((&input[1..], 0), flag));
    }

    Ok(((input, bit_offset + 1), flag))
}
