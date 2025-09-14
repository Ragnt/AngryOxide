use nom::bytes::complete::take;
use nom::IResult;

use crate::frame::components::SequenceControl;

/* pub fn parse_sequence_control(input: &[u8]) -> IResult<&[u8], SequenceControl> {
    // Use the `bits` combinator to parse bit fields
    bits::<_, _, Error<(&[u8], usize)>, _, _>(|input| {
        let (input, fragment_number): (_, u8) = take(4usize)(input)?;  // Take 4 bits for fragment number
        let (input, sequence_number): (_, u16) = take(12usize)(input)?; // Take 12 bits for sequence number
        println!("{}\n", sequence_number);
        Ok((
            input,
            SequenceControl {
                fragment_number,
                sequence_number,
            },
        ))
    })(input)
} */

pub fn parse_sequence_control(input: &[u8]) -> IResult<&[u8], SequenceControl> {
    // Read exactly 2 bytes (16 bits)
    let (remaining, sequence_control_bytes) = take(2usize)(input)?;

    // Ensure that we have exactly two bytes
    let byte1 = sequence_control_bytes[0];
    let byte2 = sequence_control_bytes[1];

    // Extract fragment number (lower 4 bits of byte1)
    let fragment_number = byte1 & 0b00001111;

    // Extract the 12-bit sequence number:
    // - The upper 4 bits from byte1, shifted right by 4 bits
    // - The entire byte2 shifted left to fill the remaining 8 bits
    let sequence_number = ((byte1 as u16 & 0b11110000) >> 4) | ((byte2 as u16) << 4);

    Ok((
        remaining,
        SequenceControl {
            fragment_number,
            sequence_number,
        },
    ))
}
