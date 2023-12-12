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

pub fn iftypes_to_string_list(iftypes: &Vec<Nl80211Iftype>) -> String {
    iftypes
        .iter()
        .map(|iftype| iftype.string())
        .collect::<Vec<&str>>()
        .join(", ")
}

pub fn wrap_in_box(input: &str) -> String {
    // Split the input string into lines
    let lines: Vec<&str> = input.split('\n').collect();

    // Determine the length of the longest line
    let max_length = lines
        .iter()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(0);

    // Calculate the total width of the box
    let box_width = max_length + 4; // 4 extra characters for borders and spaces

    // Create a new string with a top border
    let mut boxed_string = format!("┌{}┐\n", "─".repeat(box_width - 2));

    // Add each line, padded with spaces to fit the box
    for line in lines {
        let padding_length = box_width - line.chars().count() - 4; // 4 extra characters for borders and spaces
        let padding = " ".repeat(padding_length);
        boxed_string.push_str(&format!("│ {}{} │\n", line, padding));
    }

    // Add a bottom border
    boxed_string.push_str(&format!("└{}┘", "─".repeat(box_width - 2)));

    boxed_string
}

impl Interface {
    fn name_as_string(&self) -> String {
        let name = self
            .name
            .as_ref()
            .map(|n| String::from_utf8(n.clone()).unwrap_or_else(|_| "Invalid UTF-8".to_string()))
            .unwrap_or("Unknown".to_string());
        let stripped_name = name.strip_suffix('\0');
        stripped_name.unwrap().to_string()
    }

    fn index_as_string(&self) -> String {
        self.index.map_or("Unknown".to_string(), |i| i.to_string())
    }

    fn driver_as_string(&self) -> String {
        self.driver
            .as_ref()
            .unwrap_or(&"Unknown".to_string())
            .clone()
    }

    pub fn pretty_print(&self) -> String {
        let mut output = "".to_string();
        let interface_line = format!("Interface: {}", &self.name_as_string());
        let index_driver_line = format!(
            "Index: {} | Driver: {}",
            self.index_as_string(),
            self.driver_as_string()
        );
        let mode_monitor_line = format!(
            "Mode: {:?} | Active Monitor: {:?}",
            self.current_iftype.unwrap(),
            self.active_monitor.unwrap()
        );
        let modes_line = format!(
            "Modes: {}",
            iftypes_to_string_list(&self.iftypes.clone().unwrap())
        );
        let frequency_line = format!(
            "Current Frequency: {:?}",
            self.frequency.clone().unwrap().frequency.unwrap()
        );
        let lines = [
            interface_line,
            index_driver_line,
            mode_monitor_line,
            modes_line,
            frequency_line,
        ];
        for line in &lines {
            output.push_str(line);
            output.push('\n');
        }
        output.push_str(&pretty_print_band_lists(
            &self.frequency_list.clone().unwrap(),
        ));

        wrap_in_box(&output)
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
