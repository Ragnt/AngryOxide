use crate::ntlook::attr::Operstate;
use crate::ntlook::attr::{Attrs, Nl80211Attr, Nl80211ChanWidth, Nl80211Iftype};
use crate::ntlook::channels::{pretty_print_band_lists, BandList};

use libwifi::frame::components::MacAddress;
use neli::attr::Attribute;
use neli::err::DeError;

use super::WiFiChannel;

/// A struct representing a wifi interface
#[non_exhaustive]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Interface {
    /// A netlink interface index. This index is used to fetch extra information with nl80211
    pub index: Option<i32>,
    /// Interface essid
    pub ssid: Option<Vec<u8>>,
    /// Interface MAC address
    pub mac: Option<MacAddress>,
    /// Interface name (u8, String)
    pub name: Option<Vec<u8>>,
    /// Interface state (Operstate)
    pub state: Option<Operstate>,
    /// Interface frequency of the selected channel (MHz)
    pub frequency: Option<Frequency>,
    /// PowerState
    pub powerstate: Option<u32>,
    /// index of wiphy to operate on, cf. /sys/class/ieee80211/<phyname>/index
    pub phy: Option<u32>,
    /// Wireless device identifier, used for pseudo-devices that don't have a netdev
    pub device: Option<u64>,
    /// Wireless ifTypes
    pub iftypes: Option<Vec<Nl80211Iftype>>,
    /// cyrrent iftype
    pub current_iftype: Option<Nl80211Iftype>,
    /// The device driver in use
    pub driver: Option<String>,
    /// If Interface has netlink
    pub has_netlink: Option<bool>,
    /// Available Frequencies
    pub frequency_list: Option<Vec<BandList>>,
    /// Feature Flags
    pub active_monitor: Option<bool>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Frequency {
    pub frequency: Option<u32>,
    pub width: Option<Nl80211ChanWidth>,
    pub channel: Option<WiFiChannel>,
    pub pwr: Option<u32>,
}

impl Default for Frequency {
    fn default() -> Self {
        Frequency {
            frequency: Some(2412),
            width: Some(Nl80211ChanWidth::ChanWidth20Noht),
            channel: Some(WiFiChannel::Channel2GHz(1)),
            pwr: Some(0),
        }
    }
}

fn decode_iftypes(bytes: Vec<u8>) -> Vec<Nl80211Iftype> {
    bytes
        .chunks(4)
        .filter_map(|chunk| {
            if chunk.len() == 4 {
                match chunk[2] {
                    0 => Some(Nl80211Iftype::IftypeUnspecified),
                    1 => Some(Nl80211Iftype::IftypeAdhoc),
                    2 => Some(Nl80211Iftype::IftypeStation),
                    3 => Some(Nl80211Iftype::IftypeAp),
                    4 => Some(Nl80211Iftype::IftypeApVlan),
                    6 => Some(Nl80211Iftype::IftypeMonitor),
                    7 => Some(Nl80211Iftype::IftypeMeshPoint),
                    // Add other cases as needed
                    _ => None,
                }
            } else {
                None
            }
        })
        .collect()
}

pub fn iftypes_to_string_list(iftypes: Vec<Nl80211Iftype>) -> String {
    iftypes
        .iter()
        .map(|iftype| iftype.to_string())
        .collect::<Vec<&str>>()
        .join(", ")
}

impl TryFrom<Attrs<'_, Nl80211Attr>> for Interface {
    type Error = DeError;

    fn try_from(attrs: Attrs<'_, Nl80211Attr>) -> Result<Self, Self::Error> {
        let mut res = Self::default();
        let mut freq: Frequency = Frequency::default();
        for attr in attrs.iter() {
            match attr.nla_type.nla_type {
                Nl80211Attr::AttrIfindex => {
                    res.index = Some(attr.get_payload_as()?);
                }
                Nl80211Attr::AttrSsid => {
                    res.ssid = Some(attr.get_payload_as_with_len()?);
                }
                Nl80211Attr::AttrMac => {
                    let mut mac = Vec::new();
                    let vecmac: Vec<u8> = attr.get_payload_as_with_len()?;
                    for byte in vecmac {
                        mac.push(byte);
                    }

                    res.mac = Some(MacAddress(mac.try_into().unwrap()));
                }
                Nl80211Attr::AttrIfname => {
                    res.name = Some(attr.get_payload_as_with_len()?);
                }
                Nl80211Attr::AttrWiphyFreq => {
                    freq.frequency = Some(attr.get_payload_as()?);
                    freq.channel =
                        Some(WiFiChannel::from_frequency(freq.frequency.unwrap()).unwrap());
                }
                Nl80211Attr::AttrChannelWidth => {
                    freq.width = Some(attr.get_payload_as()?);
                }
                Nl80211Attr::AttrWiphyTxPowerLevel => {
                    freq.pwr = Some(attr.get_payload_as()?);
                }
                Nl80211Attr::AttrPsState => {
                    res.powerstate = Some(attr.get_payload_as()?);
                }
                Nl80211Attr::AttrWiphy => res.phy = Some(attr.get_payload_as()?),
                Nl80211Attr::AttrWdev => res.device = Some(attr.get_payload_as()?),
                Nl80211Attr::AttrSupportedIftypes => {
                    res.iftypes = Some(decode_iftypes(attr.get_payload_as_with_len()?));
                }
                Nl80211Attr::AttrIftype => {
                    res.current_iftype = Some(attr.get_payload_as()?);
                }
                _ => (),
            }
        }
        res.frequency = Some(freq);
        Ok(res)
    }
}

impl Interface {
    pub fn pretty_print(&self) -> String {
        let types: String;
        if let Some(iftypes) = self.iftypes.clone() {
            types = iftypes_to_string_list(iftypes);
        } else {
            types = "".to_string();
        }
        let str = format!(
            "================ {} ({}) ================\n - Interface Index: {}\n - Driver: {}\n - Mode: {} \n - Modes: {}\n - Active Monitor: {}\n - Current Freq: {} ({})\n - Supported Frequencies: \n{}\n========================================",
            String::from_utf8(self.name.clone().unwrap()).unwrap(),
            self.mac.as_ref().unwrap(),
            self.index.unwrap(),
            self.driver.as_ref().unwrap_or(&"Unknown".to_string()),
            self.current_iftype.unwrap().to_string(),
            types,
            self.active_monitor.unwrap(),
            self.frequency.as_ref().unwrap().frequency.map_or("None".to_string(), |value| value.to_string()),
            self.frequency.as_ref().unwrap().channel.as_ref().map_or("None".to_string(), |value| value.to_string()),
            pretty_print_band_lists(self.frequency_list.as_ref().unwrap()),
        );
        str
    }
}
