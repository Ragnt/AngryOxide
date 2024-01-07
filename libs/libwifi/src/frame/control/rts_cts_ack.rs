use crate::frame::components::{FrameControl, MacAddress};
use crate::Addresses;

/// It indicates to the Station, that a node wants to send some data.
///
/// The usual flow is `RTS -> CTS -> Data -> ACK`.
///
/// This protocol was introduced to reduce frame collisions introduced by the
/// [hidden node problem](https://en.wikipedia.org/wiki/Hidden_node_problem).
#[derive(Clone, Debug)]
pub struct Rts {
    pub frame_control: FrameControl,
    pub duration: [u8; 2],
    pub source: MacAddress,
    pub destination: MacAddress,
}

impl Addresses for Rts {
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

/// Send by a station to indicate that requesting node is allowed to send.
///
/// Part of the `RTS -> CTS -> Data -> ACK` protocol.
///
/// The protocol was introduced to reduce frame collisions introduced by the
/// [hidden node problem](https://en.wikipedia.org/wiki/Hidden_node_problem).
#[derive(Clone, Debug)]
pub struct Cts {
    pub frame_control: FrameControl,
    pub duration: [u8; 2],
    pub destination: MacAddress,
}
impl Cts {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize frame_control
        bytes.extend_from_slice(&self.frame_control.encode());

        // Serialize duration (2 bytes)
        bytes.extend_from_slice(&self.duration);

        // Serialize destination (MacAddress)
        bytes.extend_from_slice(&self.destination.encode());

        bytes
    }
}

impl Addresses for Cts {
    fn src(&self) -> Option<&MacAddress> {
        None
    }

    fn dest(&self) -> &MacAddress {
        &self.destination
    }

    fn bssid(&self) -> Option<&MacAddress> {
        None
    }
}

/// Send by the receiving station to indicate that the data has been transmitted.
///
/// Part of the `RTS -> CTS -> Data -> ACK` protocol.
///
/// The protocol was introduced to reduce frame collisions introduced by the
/// [hidden node problem](https://en.wikipedia.org/wiki/Hidden_node_problem).
#[derive(Clone, Debug)]
pub struct Ack {
    pub frame_control: FrameControl,
    pub duration: [u8; 2],
    pub destination: MacAddress,
}

impl Addresses for Ack {
    fn src(&self) -> Option<&MacAddress> {
        None
    }

    fn dest(&self) -> &MacAddress {
        &self.destination
    }

    fn bssid(&self) -> Option<&MacAddress> {
        None
    }
}

impl Ack {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize frame_control
        bytes.extend_from_slice(&self.frame_control.encode());

        // Serialize duration (2 bytes)
        bytes.extend_from_slice(&self.duration);

        // Serialize destination (MacAddress)
        bytes.extend_from_slice(&self.destination.encode());

        bytes
    }
}
