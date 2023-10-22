use std::fmt;

/// This is our representation of a MAC-address
///
/// ```
/// use libwifi::frame::components::MacAddress;
///
/// let address = MacAddress([255, 255, 255, 255, 255, 255]);
/// println!("{}", address.is_broadcast());
/// // -> true
/// ```
///
#[derive(Clone, Debug)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// Check whether this MAC addresses the whole network.
    pub fn is_broadcast(&self) -> bool {
        self.0 == [255, 255, 255, 255, 255, 255]
    }

    /// Check whether this is a group address.
    /// Group addresses start with 01:80:C2::0/24.
    pub fn is_groupcast(&self) -> bool {
        self.0[0] == 1 && self.0[1] == 128 && self.0[2] == 194
    }

    /// The 01:00:5e::0/18 space is reserved for ipv4 multicast
    pub fn is_ipv4_multicast(&self) -> bool {
        self.0[0] == 1 && self.0[1] == 0 && self.0[2] == 94
    }

    /// 33:33::0/24 is used for ipv6 neighborhood discovery.
    pub fn is_ipv6_neighborhood_discovery(&self) -> bool {
        self.0 == [51, 51, 0, 0, 0, 0]
    }

    /// The 33:33::0/24 space is reserved for ipv6 multicast
    pub fn is_ipv6_multicast(&self) -> bool {
        self.0[0] == 51 && self.0[1] == 51
    }

    /// The 01:80:c2::0/18 space is reserved for spanning-tree requests.
    pub fn is_spanning_tree(&self) -> bool {
        self.0[0] == 1 && self.0[1] == 128 && self.0[2] == 194
    }

    /// A helper function to check whether the mac address is an actual device or just some kind of
    /// "meta" mac address.
    ///
    /// This function is most likely not complete, but it already covers a cases.
    pub fn is_real_device(&self) -> bool {
        !(self.is_ipv6_multicast()
            || self.is_broadcast()
            || self.is_ipv4_multicast()
            || self.is_groupcast()
            || self.is_spanning_tree())
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum MacParseError {
    InvalidDigit,
    InvalidLength,
}

impl fmt::Display for MacParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Encountered an error while parsing a mac address.")
    }
}

impl std::error::Error for MacParseError {}

impl std::str::FromStr for MacAddress {
    type Err = MacParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut array = [0u8; 6];

        let bytes: Vec<&str> = input.split(|c| c == ':').collect();
        if bytes.len() != 6 {
            return Err(MacParseError::InvalidLength);
        }

        for (count, byte) in bytes.iter().enumerate() {
            array[count] = u8::from_str_radix(byte, 16).map_err(|_| MacParseError::InvalidDigit)?;
        }

        Ok(MacAddress(array))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_broadcast() {
        let mac = MacAddress([255, 255, 255, 255, 255, 255]);
        assert!(mac.is_broadcast())
    }

    #[test]
    fn test_format() {
        let mac = MacAddress([12, 157, 146, 197, 170, 127]);
        assert_eq!("0c:9d:92:c5:aa:7f", mac.to_string())
    }
}
