use std::fmt;
use std::hash::{Hash, Hasher};

use rand::{thread_rng, Rng, RngCore};

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
#[derive(Clone, Debug, Eq, PartialEq, Copy, Ord, PartialOrd)]
pub struct MacAddress(pub [u8; 6]);

impl Hash for MacAddress {
    fn hash<H: Hasher>(&self, _state: &mut H) {
        // Implement hashing here
    }
}

impl MacAddress {
    pub fn from_vec(vec: Vec<u8>) -> Option<MacAddress> {
        if vec.len() == 6 {
            let mut arr = [0u8; 6];
            for (place, element) in arr.iter_mut().zip(vec.iter()) {
                *place = *element;
            }
            Some(MacAddress(arr))
        } else {
            // Return None if the Vec is not exactly 6 bytes long
            None
        }
    }

    /// Generate u64.
    pub fn to_u64(&self) -> u64 {
        let bytes = self.0;
        (bytes[0] as u64) << 40
            | (bytes[1] as u64) << 32
            | (bytes[2] as u64) << 24
            | (bytes[3] as u64) << 16
            | (bytes[4] as u64) << 8
            | (bytes[5] as u64)
    }

    /// Generate string with delimitters.
    pub fn to_long_string(&self) -> String {
        format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5],
        )
    }

    /// Generate random valid mac
    pub fn random() -> Self {
        loop {
            let mac = MacAddress(generate_random_bytes(6).try_into().unwrap());
            if mac.is_real_device() {
                return mac;
            }
        }
    }

    pub fn broadcast() -> Self {
        MacAddress([255, 255, 255, 255, 255, 255])
    }

    pub fn zeroed() -> Self {
        MacAddress([0, 0, 0, 0, 0, 0])
    }

    /// Generate a random MAC address using the same OUI as the given MAC address
    pub fn random_with_oui(other: &MacAddress) -> Self {
        let mut rng = rand::thread_rng();
        let mut new_mac = other.0;
        new_mac[3..6].fill_with(|| rng.gen());
        MacAddress(new_mac)
    }

    /// Encode mac address for network.
    pub fn encode(&self) -> [u8; 6] {
        self.0
    }

    /// Check if this is a private address (locally set bit)
    pub fn is_private(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    /// Check if this is a multicast address
    pub fn is_mcast(&self) -> bool {
        self.0[0] % 2 == 1
    }

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
            || self.is_spanning_tree()
            || self.is_mcast())
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5],
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

        let input_lower = input.to_lowercase();
        // Check if the input contains colons, and split accordingly
        let bytes: Vec<&str> = if input_lower.contains(':') {
            input_lower.split(':').collect()
        } else if input.contains('-') {
            input_lower.split('-').collect()
        } else if input_lower.len() == 12 {
            // If the input doesn't contain colons and is 12 characters long
            input_lower
                .as_bytes()
                .chunks(2)
                .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
                .collect()
        } else {
            return Err(MacParseError::InvalidLength);
        };

        // Validate the number of bytes
        if bytes.len() != 6 {
            return Err(MacParseError::InvalidLength);
        }

        // Parse each byte
        for (count, byte) in bytes.iter().enumerate() {
            array[count] = u8::from_str_radix(byte, 16).map_err(|_| MacParseError::InvalidDigit)?;
        }

        Ok(MacAddress(array))
    }
}

pub fn generate_random_bytes(x: usize) -> Vec<u8> {
    let mut rng = thread_rng();
    let length = x;
    let mut bytes = vec![0u8; length];
    rng.fill_bytes(&mut bytes);
    // Ensure the first byte is even
    if !bytes.is_empty() {
        bytes[0] &= 0xFE; // 0xFE is 11111110 in binary
    }

    bytes
}

// We need to be able to glob against mac addresses, so a MacAddressGlob will be a mac address that we can do a match against.

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct MacAddressGlob {
    pattern: [u8; 6],
    mask: [u8; 6],
}

impl fmt::Display for MacAddressGlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for i in 0..6 {
            if self.mask[i] == 0 {
                write!(f, "*")?;
            } else if self.mask[i] == 0xF0 {
                write!(f, "{:x}*", self.pattern[i] >> 4)?;
            } else {
                write!(f, "{:02x}", self.pattern[i])?;
            }
            if i < 5 {
                write!(f, ":")?;
            }
        }
        Ok(())
    }
}

pub enum MacGlobParseError {
    InvalidDigit,
    InvalidLength,
}

impl fmt::Display for MacGlobParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MacGlobParseError::InvalidDigit => write!(f, "Invalid hex digit in pattern"),
            MacGlobParseError::InvalidLength => write!(f, "Pattern is too long"),
        }
    }
}

impl MacAddressGlob {
    pub fn new(pattern: &str) -> Result<Self, MacGlobParseError> {
        let normalized_pattern = pattern.to_lowercase().replace(&[':', '-', '.'][..], "");

        if normalized_pattern.len() > 12 {
            return Err(MacGlobParseError::InvalidLength);
        }

        let mut pattern_bytes = [0u8; 6];
        let mut mask_bytes = [0u8; 6];

        for (i, chunk) in normalized_pattern.as_bytes().chunks(2).enumerate() {
            if i >= 6 {
                return Err(MacGlobParseError::InvalidLength);
            }
            let (pattern_byte, mask_byte) = match chunk {
                [b'*'] => (0x00, 0x00),
                [high, b'*'] => {
                    let high_nibble = match high {
                        b'0'..=b'9' => high - b'0',
                        b'a'..=b'f' => high - b'a' + 10,
                        _ => return Err(MacGlobParseError::InvalidDigit),
                    };
                    (high_nibble << 4, 0xF0)
                }
                [high, low] => {
                    let high_nibble = match high {
                        b'0'..=b'9' => high - b'0',
                        b'a'..=b'f' => high - b'a' + 10,
                        _ => return Err(MacGlobParseError::InvalidDigit),
                    };
                    let low_nibble = match low {
                        b'0'..=b'9' => low - b'0',
                        b'a'..=b'f' => low - b'a' + 10,
                        _ => return Err(MacGlobParseError::InvalidDigit),
                    };
                    (high_nibble << 4 | low_nibble, 0xFF)
                }
                _ => return Err(MacGlobParseError::InvalidDigit),
            };
            pattern_bytes[i] = pattern_byte;
            mask_bytes[i] = mask_byte;
        }

        // Handle patterns that are not full 6 bytes by filling remaining bytes with wildcards
        for i in (normalized_pattern.len() / 2)..6 {
            pattern_bytes[i] = 0x00;
            mask_bytes[i] = 0x00;
        }

        Ok(Self {
            pattern: pattern_bytes,
            mask: mask_bytes,
        })
    }

    pub fn from_mac_address(mac: &MacAddress) -> Self {
        Self {
            pattern: mac.0,
            mask: [0xFF; 6],
        }
    }

    pub fn matches(&self, mac: &MacAddress) -> bool {
        for i in 0..6 {
            if (mac.0[i] & self.mask[i]) != (self.pattern[i] & self.mask[i]) {
                return false;
            }
        }
        true
    }
}
