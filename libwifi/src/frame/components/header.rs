use super::{FrameControl, MacAddress, SequenceControl};
use crate::traits::Addresses;

/// Representation of a management frame header. This format is used by all management frames!
///
/// This struct implements the `Addresses` trait, which provides the `src`, `dest` and `bssid`
/// functions.
///
/// Structure of a management header:
///
/// **Bytes 0-1** \
/// These contain protocol meta information and flags. These have already been parsed!
/// Take a look at the [FrameControl] struct for more information.
///
/// **Bytes 2-3** \
/// Those are the duration bytes. These are always present!
/// They are quite specific and not explained here.
///
/// **Bytes 4-29** \
/// These contain all important address information.
///
/// byte 4-9: Address 1. Always present!
/// byte 10-15: Address 2.
/// byte 16-21: Address 3.
/// byte 22-23: Sequence Control.
///
/// **Sequence Control:** \
/// Contains the FragmentNumber and SequenceNumber that define the main frame and the number of fragments in the frame.
#[derive(Clone, Debug)]
pub struct ManagementHeader {
    pub frame_control: FrameControl,
    pub duration: [u8; 2],
    pub address_1: MacAddress,
    pub address_2: MacAddress,
    pub address_3: MacAddress,
    pub sequence_control: SequenceControl,
}

/// Which address is used in which way, depends on a combination of
/// - two flags in the FrameControl header.
/// - the Type/Subtype constellation.
///
/// A rule of thumb is this:
///
/// **Address 1:** \
/// The recipient station address.
/// If `to_ds` is set, this is the AP address.
/// If `from_ds` is set then this is the station address
///
/// **Address 2:** \
/// The transmitter station address.
/// If `from_ds` is set, this is the AP address.
/// If `to_ds` is set then this is the station address.
///
/// **Address 3:** \
/// If Address 1 contains the destination address then Address 3 will contain the source address.
/// Similarly, if Address 2 contains the source address then Address 3 will contain the destination address.
///
/// **Sequence Control:** \
/// Contains the FragmentNumber and SequenceNumber that define the main frame and the number of fragments in the frame.
impl Addresses for ManagementHeader {
    /// Return the mac address of the sender
    fn src(&self) -> Option<&MacAddress> {
        let frame_control = &self.frame_control;
        if frame_control.to_ds() {
            Some(&self.address_3)
        } else if frame_control.from_ds() {
            Some(&self.address_1)
        } else {
            Some(&self.address_2)
        }
    }

    /// Return the mac address of the receiver.
    /// A full `ff:ff:..` usually indicates a undirected broadcast.
    fn dest(&self) -> &MacAddress {
        let frame_control = &self.frame_control;
        if frame_control.to_ds() && frame_control.from_ds() {
            &self.address_3
        } else if frame_control.to_ds() {
            &self.address_2
        } else if frame_control.from_ds() {
            &self.address_3
        } else {
            &self.address_1
        }
    }

    /// The BSSID for this request.
    /// In most cases, this is expected to be present.
    /// The only time it's not, is in a wireless distributed system (WDS).
    fn bssid(&self) -> Option<&MacAddress> {
        let frame_control = &self.frame_control;
        if frame_control.to_ds() {
            Some(&self.address_1)
        } else if frame_control.from_ds() {
            Some(&self.address_2)
        } else {
            Some(&self.address_3)
        }
    }
}

/// Representation of a data frame header. This format is used by all data frames!
///
/// It's very similar to the format of the management header, but there are some slight
/// differences, since they allow a forth address and Quality of Service (QoS) data.
///
/// Structure:
///
/// **Bytes 0-1** \
/// These contain protocol meta information and flags. These have already been parsed!
/// Take a look at the [FrameControl] struct for more information.
///
/// **Bytes 2-3** \
/// Those are the duration bytes. These are always present!
/// They are quite specific and not explained here.
///
/// **Bytes 4-29** \
/// These contain all important address information.
///
/// byte 4-9: Address 1. Always present!
/// byte 10-15: Address 2.
/// byte 16-21: Address 3.
/// byte 22-23: Sequence Control.
/// byte 24-30: Address 4 (Exists if to_ds and from_ds is set)
/// byte 31-32: Quality of Service bytes, only exists in QoS Data frames.
#[derive(Clone, Debug)]
pub struct DataHeader {
    pub frame_control: FrameControl,
    pub duration: [u8; 2],
    pub address_1: MacAddress,
    pub address_2: MacAddress,
    pub address_3: MacAddress,
    pub sequence_control: SequenceControl,
    pub address_4: Option<MacAddress>,
    pub qos: Option<[u8; 2]>,
}

impl Addresses for DataHeader {
    /// Return the mac address of the sender
    fn src(&self) -> Option<&MacAddress> {
        if self.frame_control.to_ds() && self.frame_control.from_ds() {
            // This should be safe.
            // If both to_ds and from_ds are true, we always read the forth address.
            self.address_4.as_ref()
        } else if self.frame_control.to_ds() {
            Some(&self.address_3)
        } else if self.frame_control.from_ds() {
            Some(&self.address_1)
        } else {
            Some(&self.address_2)
        }
    }

    /// Return the mac address of the receiver.
    /// A full `ff:ff:..` usually indicates a undirected broadcast.
    fn dest(&self) -> &MacAddress {
        if self.frame_control.to_ds() && self.frame_control.from_ds() {
            &self.address_3
        } else if self.frame_control.to_ds() {
            &self.address_2
        } else if self.frame_control.from_ds() {
            &self.address_3
        } else {
            &self.address_1
        }
    }

    /// The BSSID for this request.
    /// In most cases, this is expected to be present.
    /// The only time it's not, is in a wireless distributed system (WDS).
    fn bssid(&self) -> Option<&MacAddress> {
        if self.frame_control.to_ds() && self.frame_control.from_ds() {
            None
        } else if self.frame_control.to_ds() {
            Some(&self.address_1)
        } else if self.frame_control.from_ds() {
            Some(&self.address_2)
        } else {
            self.address_4.as_ref()
        }
    }
}
