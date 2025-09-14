#[derive(Clone, Debug)]
pub struct SequenceControl {
    /// The 4 bit fragment number from a sequence control field.
    pub fragment_number: u8,
    /// The 12 bit sequence number from a sequence control field.
    pub sequence_number: u16,
}

impl SequenceControl {
    pub fn encode(&self) -> [u8; 2] {
        // The sequence number occupies the upper 12 bits
        let sequence_number_bits = (self.sequence_number & 0x0FFF) << 4;
        // The fragment number occupies the lower 4 bits
        let fragment_number_bits = self.fragment_number & 0x0F;

        let combined = sequence_number_bits | fragment_number_bits as u16;

        // Convert to two bytes in little-endian format
        [combined as u8, (combined >> 8) as u8]
    }
}
