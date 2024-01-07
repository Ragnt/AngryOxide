use nom::bytes::complete::take;
use nom::IResult;

use crate::frame::components::MacAddress;

mod frame_control;
mod header;
mod sequence_control;
mod station_info;

pub use frame_control::parse_frame_control;
pub use header::*;
pub use sequence_control::parse_sequence_control;
pub use station_info::parse_station_info;

/// Parse mac addresses.
/// Just take 6 bytes, clone them and create a new MacAddress struct from those bytes.
pub fn parse_mac(input: &[u8]) -> IResult<&[u8], MacAddress> {
    let (remaining, bytes) = take(6usize)(input)?;
    Ok((remaining, MacAddress(clone_slice::<6>(bytes))))
}

/// A convenience method to get a fixed-size slice copyfrom any slice.
/// This will always use the first `X` bytes of the slice.
pub(crate) fn clone_slice<const X: usize>(slice: &[u8]) -> [u8; X] {
    let mut cloned_slice: [u8; X] = [0; X];
    cloned_slice.copy_from_slice(&slice[0..X]);

    cloned_slice
}
