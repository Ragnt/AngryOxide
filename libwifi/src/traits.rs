use crate::frame::components::MacAddress;
use crate::frame::*;
use enum_dispatch::enum_dispatch;

/// Helper trait to easily access source, destination and bssid on frames.
#[enum_dispatch]
pub trait Addresses {
    /// Returns the sender of the Frame.
    /// This isn't always send in every frame (e.g. CTS).
    fn src(&self) -> Option<&MacAddress>;

    /// Returns the destination of the Frame.
    /// This should always be present.
    fn dest(&self) -> &MacAddress;

    /// This isn't always send in every frame (e.g. RTS).
    fn bssid(&self) -> Option<&MacAddress>;
}
