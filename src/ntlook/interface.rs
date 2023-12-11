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
        .map(|iftype| iftype.string())
        .collect::<Vec<&str>>()
        .join(", ")
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
            "================ {} ({}) ================ 
            - Interface Index: {} 
            - Driver: {} 
            - Mode: {} 
            - Modes: {}
            - Active Monitor: {}
            - Current Freq: {} ({})
            - Supported Frequencies: 
            {}
            ========================================",
            String::from_utf8(self.name.clone().unwrap()).unwrap(),
            self.mac.as_ref().unwrap(),
            self.index.unwrap(),
            self.driver.as_ref().unwrap_or(&"Unknown".to_string()),
            self.current_iftype.unwrap().string(),
            types,
            self.active_monitor.unwrap_or_default(),
            self.frequency
                .as_ref()
                .unwrap()
                .frequency
                .map_or("None".to_string(), |value| value.to_string()),
            self.frequency
                .as_ref()
                .unwrap()
                .channel
                .as_ref()
                .map_or("None".to_string(), |value| value.to_string()),
            pretty_print_band_lists(self.frequency_list.as_ref().unwrap_or(&Vec::new())),
        );
        str
    }

    pub fn merge_with(&mut self, other: Interface) {
        if self.index.is_none() {
            self.index = other.index;
        }
        if self.ssid.is_none() {
            self.ssid = other.ssid;
        }
        if self.mac.is_none() {
            self.mac = other.mac;
        }
        if self.name.is_none() {
            self.name = other.name;
        }
        if self.state.is_none() {
            self.state = other.state;
        }
        if self.frequency.is_none() {
            self.frequency = other.frequency;
        }
        if self.powerstate.is_none() {
            self.powerstate = other.powerstate;
        }
        if self.phy.is_none() {
            self.phy = other.phy;
        }
        if self.device.is_none() {
            self.device = other.device;
        }
        if self.iftypes.is_none() {
            self.iftypes = other.iftypes;
        }
        if self.current_iftype.is_none() {
            self.current_iftype = other.current_iftype;
        }
        if self.driver.is_none() {
            self.driver = other.driver;
        }
        if self.has_netlink.is_none() {
            self.has_netlink = other.has_netlink;
        }
        if self.frequency_list.is_none() {
            self.frequency_list = other.frequency_list;
        }
        if self.active_monitor.is_none() {
            self.active_monitor = other.active_monitor;
        }
    }
}
