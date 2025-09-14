use crate::frame::components::{FrameControl, MacAddress, SequenceControl};
use crate::Addresses;

#[derive(Clone, Debug)]
pub enum BlockAckMode {
    /// Deprecated ack format, which uses a 128 byte map for acknowledgment.
    BasicBlockAck,
    /// BlockAck used for simple TID acknowledgments, with a 8 byte map.
    CompressedBlockAck,
    /// Multiple Transaction Ids (TID)/Packets will should be acknowledged.
    /// Uses compressed 8 byte maps for acknowledgment.
    MultiTidBlockAck,
}

#[derive(Clone, Debug)]
pub enum BlockAckInfo {
    /// A simple BlockAck response with an 128 bytes bitmap.
    /// This is deprecated and should barely be used in practice.
    Basic((u8, SequenceControl, [u8; 128])),
    /// A vector of tuples of (TID, SequenceControl, 8byte Bitmap).
    Compressed(Vec<(u8, SequenceControl, u64)>),
}

/// Used in a BlockAck session to acknowlede sent packets.
///
/// Once the BlockAck session is established the AP and the requesting station can partake
/// in a contention free burst within the scope of the session.
/// After the frame burst is complete and the acknowledgment has been requested,
/// this frame is sent to acknowledge any received frames.
///
/// [Guide](https://www.hitchhikersguidetolearning.com/2017/09/17/block-ack-frame-formats-block-ack-request/).
#[derive(Clone, Debug)]
pub struct BlockAckRequest {
    pub frame_control: FrameControl,
    pub duration: [u8; 2],
    pub source: MacAddress,
    pub destination: MacAddress,
    /// The acknowledgment policy flag.
    ///
    /// `true`: No immediate acknowledgment is required. \
    /// `false`: Immediate acknowledgment is required.
    pub policy: bool,
    pub mode: BlockAckMode,
    /// The TID's and the respective sequence control bytes, for which the BlockAck has been
    /// requested.
    pub requested_tids: Vec<(u8, SequenceControl)>,
}

impl Addresses for BlockAckRequest {
    fn src(&self) -> Option<&MacAddress> {
        Some(&self.source)
    }

    fn dest(&self) -> &MacAddress {
        &self.destination
    }

    fn bssid(&self) -> Option<&MacAddress> {
        None
    }
}

/// Used in a BlockAck session to request acknowledgment of sent packets.
///
/// Once the BlockAck session is established the AP and the requesting station can partake
/// in a contention free burst within the scope of the session.
/// After the frame burst is complete, the WLAN station will send a [BlockAckRequest] to the
/// AP requesting the AP to acknowledge the frames the station just sent.
///
/// The AP will then respond with a [BlockAck] frame, acknowledging all received packets.
///
/// [Guide](https://www.hitchhikersguidetolearning.com/2017/09/17/block-ack-frame-formats-block-ack-request/).
#[derive(Clone, Debug)]
pub struct BlockAck {
    pub frame_control: FrameControl,
    pub duration: [u8; 2],
    pub source: MacAddress,
    pub destination: MacAddress,
    /// The acknowledgment policy flag.
    ///
    /// `true`: No immediate acknowledgment is required. \
    /// `false`: Immediate acknowledgment is required.
    pub policy: bool,
    pub mode: BlockAckMode,
    /// The TID's and the respective sequence control bytes, for which the BlockAck has been
    /// requested.
    pub acks: BlockAckInfo,
}

impl Addresses for BlockAck {
    fn src(&self) -> Option<&MacAddress> {
        Some(&self.source)
    }

    fn dest(&self) -> &MacAddress {
        &self.destination
    }

    fn bssid(&self) -> Option<&MacAddress> {
        None
    }
}
