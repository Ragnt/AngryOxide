use std::fmt;

use crate::ntlook::attr::{Attrs, Nl80211Attr, Nl80211Bss};

use neli::attr::Attribute;
use neli::err::DeError;

/// A struct representing a BSS (Basic Service Set)
#[non_exhaustive]
#[derive(Default, Clone, PartialEq, Eq)]
pub struct Bss {
    /// BSSID
    pub bssid: Option<Vec<u8>>,
    /// Frequency in MHz
    pub frequency: Option<u32>,
    /// Beacon interval of the (I)BSS
    pub beacon_interval: Option<u16>,
    /// Age of this BSS entry in ms
    pub seen_ms_ago: Option<u32>,
    /// Status, if this BSS is "used"
    pub status: Option<u32>,
    /// Signal strength of probe response/beacon in mBm (100 * dBm)
    pub signal: Option<i32>,
    /// binary attribute containing the raw information elements from the probe response/beacon.
    pub information_elements: Option<Vec<u8>>,
}

impl TryFrom<Attrs<'_, Nl80211Attr>> for Bss {
    type Error = DeError;

    fn try_from(attrs: Attrs<'_, Nl80211Attr>) -> Result<Self, Self::Error> {
        let mut res = Self::default();
        if let Some(bss) = attrs.get_attribute(Nl80211Attr::AttrBss) {
            let attrs = bss.get_attr_handle::<Nl80211Bss>()?;
            for attr in attrs.iter() {
                match attr.nla_type.nla_type {
                    Nl80211Bss::BssBssid => {
                        res.bssid = Some(attr.get_payload_as_with_len()?);
                    }
                    Nl80211Bss::BssFrequency => {
                        res.frequency = Some(attr.get_payload_as()?);
                    }
                    Nl80211Bss::BssBeaconInterval => {
                        res.beacon_interval = Some(attr.get_payload_as()?);
                    }
                    Nl80211Bss::BssSeenMsAgo => {
                        res.seen_ms_ago = Some(attr.get_payload_as()?);
                    }
                    Nl80211Bss::BssStatus => {
                        res.status = Some(attr.get_payload_as()?);
                    }
                    Nl80211Bss::BssSignalMbm => {
                        res.signal = Some(attr.get_payload_as()?);
                    }
                    Nl80211Bss::BssInformationElements => {
                        res.information_elements = Some(attr.get_payload_as_with_len()?);
                    }
                    _ => (),
                }
            }
        }
        Ok(res)
    }
}

impl fmt::Debug for Bss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bss")
            .field("bssid", &self.bssid)
            .field("frequency", &self.frequency)
            .field("beacon_interval", &self.beacon_interval)
            .field("seen_ms_ago", &self.seen_ms_ago)
            .field("status", &self.status)
            .field("signal", &self.signal)
            .field("information_elements", &"...")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod test_bss {
    use super::*;
    use crate::ntlook::attr::Nl80211Attr::*;
    use neli::attr::AttrHandle;
    use neli::genl::{AttrType, Nlattr};
    use neli::types::Buffer;

    fn new_attr(t: Nl80211Attr, d: Vec<u8>) -> Nlattr<Nl80211Attr, Buffer> {
        Nlattr {
            nla_len: (4 + d.len()) as _,
            nla_type: AttrType {
                nla_nested: false,
                nla_network_order: true,
                nla_type: t,
            },
            nla_payload: d.into(),
        }
    }

    #[test]
    fn test_parse() {
        let handler = vec![
            new_attr(AttrGeneration, vec![28, 4, 0, 0]),
            new_attr(AttrIfindex, vec![3, 0, 0, 0]),
            new_attr(AttrWdev, vec![1, 0, 0, 0, 0, 0, 0, 0]),
            new_attr(
                AttrBss,
                vec![
                    10, 0, 1, 0, 255, 255, 255, 255, 255, 255, 0, 0, 4, 0, 14, 0, 12, 0, 3, 0, 132,
                    12, 93, 163, 39, 0, 0, 0, 95, 1, 6, 0, 0, 8, 83, 70, 82, 45, 49, 99, 50, 56, 1,
                    8, 130, 132, 139, 150, 36, 48, 72, 108, 3, 1, 1, 7, 6, 68, 69, 32, 1, 13, 20,
                    32, 1, 0, 35, 2, 16, 0, 42, 1, 0, 50, 4, 12, 18, 24, 96, 48, 24, 1, 0, 0, 15,
                    172, 2, 2, 0, 0, 15, 172, 4, 0, 15, 172, 2, 1, 0, 0, 15, 172, 2, 12, 0, 11, 5,
                    1, 0, 80, 0, 0, 70, 5, 114, 8, 1, 0, 0, 45, 26, 188, 9, 27, 255, 255, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 61, 22, 1, 8, 4, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 8, 4, 0, 8, 0, 0, 0, 0,
                    64, 221, 131, 0, 80, 242, 4, 16, 74, 0, 1, 16, 16, 68, 0, 1, 2, 16, 59, 0, 1,
                    3, 16, 71, 0, 16, 65, 133, 194, 155, 156, 12, 135, 126, 154, 135, 125, 82, 84,
                    30, 42, 138, 16, 33, 0, 8, 83, 97, 103, 101, 109, 99, 111, 109, 16, 35, 0, 8,
                    83, 97, 103, 101, 109, 99, 111, 109, 16, 36, 0, 6, 49, 50, 51, 52, 53, 54, 16,
                    66, 0, 7, 48, 48, 48, 48, 48, 48, 49, 16, 84, 0, 8, 0, 6, 0, 80, 242, 4, 0, 1,
                    16, 17, 0, 10, 83, 97, 103, 101, 109, 99, 111, 109, 65, 80, 16, 8, 0, 2, 32, 8,
                    16, 60, 0, 1, 3, 16, 73, 0, 6, 0, 55, 42, 0, 1, 32, 221, 9, 0, 16, 24, 2, 1, 0,
                    12, 0, 0, 221, 26, 0, 80, 242, 1, 1, 0, 0, 80, 242, 2, 2, 0, 0, 80, 242, 4, 0,
                    80, 242, 2, 1, 0, 0, 80, 242, 2, 221, 24, 0, 80, 242, 2, 1, 1, 132, 0, 3, 164,
                    0, 0, 39, 164, 0, 0, 66, 67, 94, 0, 98, 50, 47, 0, 0, 12, 0, 13, 0, 187, 118,
                    116, 163, 39, 0, 0, 0, 19, 1, 11, 0, 0, 8, 83, 70, 82, 45, 49, 99, 50, 56, 1,
                    8, 130, 132, 139, 150, 36, 48, 72, 108, 3, 1, 1, 5, 4, 0, 1, 0, 0, 7, 6, 68,
                    69, 32, 1, 13, 20, 32, 1, 0, 35, 2, 16, 0, 42, 1, 0, 50, 4, 12, 18, 24, 96, 48,
                    24, 1, 0, 0, 15, 172, 2, 2, 0, 0, 15, 172, 4, 0, 15, 172, 2, 1, 0, 0, 15, 172,
                    2, 12, 0, 11, 5, 1, 0, 80, 0, 0, 70, 5, 114, 8, 1, 0, 0, 45, 26, 188, 9, 27,
                    255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 61,
                    22, 1, 8, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 8,
                    4, 0, 8, 0, 0, 0, 0, 64, 221, 49, 0, 80, 242, 4, 16, 74, 0, 1, 16, 16, 68, 0,
                    1, 2, 16, 71, 0, 16, 65, 133, 194, 155, 156, 12, 135, 126, 154, 135, 125, 82,
                    84, 30, 42, 138, 16, 60, 0, 1, 3, 16, 73, 0, 6, 0, 55, 42, 0, 1, 32, 221, 9, 0,
                    16, 24, 2, 1, 0, 12, 0, 0, 221, 26, 0, 80, 242, 1, 1, 0, 0, 80, 242, 2, 2, 0,
                    0, 80, 242, 4, 0, 80, 242, 2, 1, 0, 0, 80, 242, 2, 221, 24, 0, 80, 242, 2, 1,
                    1, 132, 0, 3, 164, 0, 0, 39, 164, 0, 0, 66, 67, 94, 0, 98, 50, 47, 0, 0, 6, 0,
                    4, 0, 100, 0, 0, 0, 6, 0, 5, 0, 17, 21, 0, 0, 8, 0, 2, 0, 108, 9, 0, 0, 8, 0,
                    12, 0, 0, 0, 0, 0, 8, 0, 10, 0, 100, 0, 0, 0, 8, 0, 7, 0, 76, 235, 255, 255, 8,
                    0, 9, 0, 1, 0, 0, 0,
                ],
            ),
        ];

        let bss: Bss = AttrHandle::new(handler.into_iter().collect())
            .try_into()
            .unwrap();
        let expected_bss = Bss {
            bssid: Some(vec![255, 255, 255, 255, 255, 255]),
            frequency: Some(u32::from_le_bytes([108, 9, 0, 0])),
            beacon_interval: Some(u16::from_le_bytes([100, 0])),
            seen_ms_ago: Some(u32::from_le_bytes([100, 0, 0, 0])),
            status: Some(u32::from_le_bytes([1, 0, 0, 0])),
            signal: Some(i32::from_le_bytes([76, 235, 255, 255])),
            information_elements: Some(vec![
                0, 8, 83, 70, 82, 45, 49, 99, 50, 56, 1, 8, 130, 132, 139, 150, 36, 48, 72, 108, 3,
                1, 1, 7, 6, 68, 69, 32, 1, 13, 20, 32, 1, 0, 35, 2, 16, 0, 42, 1, 0, 50, 4, 12, 18,
                24, 96, 48, 24, 1, 0, 0, 15, 172, 2, 2, 0, 0, 15, 172, 4, 0, 15, 172, 2, 1, 0, 0,
                15, 172, 2, 12, 0, 11, 5, 1, 0, 80, 0, 0, 70, 5, 114, 8, 1, 0, 0, 45, 26, 188, 9,
                27, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 61,
                22, 1, 8, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 8, 4, 0,
                8, 0, 0, 0, 0, 64, 221, 131, 0, 80, 242, 4, 16, 74, 0, 1, 16, 16, 68, 0, 1, 2, 16,
                59, 0, 1, 3, 16, 71, 0, 16, 65, 133, 194, 155, 156, 12, 135, 126, 154, 135, 125,
                82, 84, 30, 42, 138, 16, 33, 0, 8, 83, 97, 103, 101, 109, 99, 111, 109, 16, 35, 0,
                8, 83, 97, 103, 101, 109, 99, 111, 109, 16, 36, 0, 6, 49, 50, 51, 52, 53, 54, 16,
                66, 0, 7, 48, 48, 48, 48, 48, 48, 49, 16, 84, 0, 8, 0, 6, 0, 80, 242, 4, 0, 1, 16,
                17, 0, 10, 83, 97, 103, 101, 109, 99, 111, 109, 65, 80, 16, 8, 0, 2, 32, 8, 16, 60,
                0, 1, 3, 16, 73, 0, 6, 0, 55, 42, 0, 1, 32, 221, 9, 0, 16, 24, 2, 1, 0, 12, 0, 0,
                221, 26, 0, 80, 242, 1, 1, 0, 0, 80, 242, 2, 2, 0, 0, 80, 242, 4, 0, 80, 242, 2, 1,
                0, 0, 80, 242, 2, 221, 24, 0, 80, 242, 2, 1, 1, 132, 0, 3, 164, 0, 0, 39, 164, 0,
                0, 66, 67, 94, 0, 98, 50, 47, 0,
            ]),
        };

        assert_eq!(bss, expected_bss)
    }
}
