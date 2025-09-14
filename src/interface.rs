// Platform abstraction layer for wireless interface operations

#[cfg(target_os = "macos")]
use std::collections::HashMap;

#[cfg(target_os = "linux")]
use nl80211_ng::{
    channels::{freq_to_band, map_str_to_band_and_channel},
    get_interface_info_idx, set_interface_chan,
};

// Re-export common types that are used throughout the codebase
#[cfg(target_os = "linux")]
pub use nl80211_ng::attr::Nl80211Iftype;
#[cfg(target_os = "linux")]
pub use nl80211_ng::channels::WiFiBand;
#[cfg(target_os = "linux")]
pub use nl80211_ng::Nl80211;

// Create an extension trait for Interface on Linux
#[cfg(target_os = "linux")]
pub trait InterfaceExt {
    fn name_as_string(&self) -> String;
    fn driver_as_string(&self) -> String;
}

#[cfg(target_os = "linux")]
impl InterfaceExt for nl80211_ng::Interface {
    fn name_as_string(&self) -> String {
        self.name
            .clone()
            .and_then(|n| String::from_utf8(n).ok())
            .unwrap_or_else(|| "unknown".to_string())
    }

    fn driver_as_string(&self) -> String {
        // nl80211_ng::Interface doesn't have a driver field on Linux
        "nl80211".to_string()
    }
}

#[cfg(target_os = "linux")]
pub use nl80211_ng::Interface;

// Create a wrapper type for Band to add the to_u8() method
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Band(WiFiBand);

#[cfg(target_os = "linux")]
impl Band {
    #[allow(clippy::wrong_self_convention)]
    pub fn to_u8(&self) -> u8 {
        match self.0 {
            WiFiBand::Band2GHz => 0,
            WiFiBand::Band5GHz => 1,
            WiFiBand::Band6GHz => 2,
            WiFiBand::Band60GHz => 3,
            _ => 255, // Handle any unknown bands
        }
    }


    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Band(WiFiBand::Band2GHz),
            1 => Band(WiFiBand::Band5GHz),
            2 => Band(WiFiBand::Band6GHz),
            3 => Band(WiFiBand::Band60GHz),
            _ => Band(WiFiBand::Band2GHz), // Default to 2.4GHz for unknown
        }
    }

    pub const UNKNOWN: Band = Band(WiFiBand::Band2GHz); // Placeholder for Unknown
    pub const BAND_2_4_GHZ: Band = Band(WiFiBand::Band2GHz);
    pub const BAND_5_GHZ: Band = Band(WiFiBand::Band5GHz);
    pub const BAND_6_GHZ: Band = Band(WiFiBand::Band6GHz);
    pub const BAND_60_GHZ: Band = Band(WiFiBand::Band60GHz);
}

#[cfg(target_os = "linux")]
impl From<WiFiBand> for Band {
    fn from(band: WiFiBand) -> Self {
        Band(band)
    }
}

#[cfg(target_os = "linux")]
impl From<Band> for WiFiBand {
    fn from(band: Band) -> Self {
        band.0
    }
}

#[cfg(target_os = "linux")]
impl std::fmt::Display for Band {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let band_str = match self.0 {
            WiFiBand::Band2GHz => "2.4GHz",
            WiFiBand::Band5GHz => "5GHz",
            WiFiBand::Band6GHz => "6GHz",
            WiFiBand::Band60GHz => "60GHz",
            _ => "Unknown",
        };
        write!(f, "{}", band_str)
    }
}

// For macOS, we need to define compatible types
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Default)]
pub struct Frequency {
    pub frequency: Option<u32>,
    pub width: Option<u32>,
    pub channel: Option<u32>,
    pub pwr: Option<u32>,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
pub struct Interface {
    pub index: Option<u32>,
    pub ssid: Option<Vec<u8>>,
    pub name: Option<Vec<u8>>,
    pub mac: Option<Vec<u8>>,
    pub frequency: Frequency,
    pub phy: Option<u32>,
    pub phy_name: u32,
    pub device: Option<u64>,
    pub current_iftype: Option<Nl80211Iftype>,
    pub driver: Option<String>,
}

#[cfg(target_os = "macos")]
impl Interface {
    pub fn name_as_string(&self) -> String {
        self.name
            .as_ref()
            .map(|n| String::from_utf8_lossy(n).to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }

    pub fn driver_as_string(&self) -> String {
        self.driver.clone().unwrap_or_else(|| "unknown".to_string())
    }

    pub fn get_frequency_list_simple(&self) -> Option<HashMap<u8, Vec<u32>>> {
        use std::collections::HashMap;

        let mut band_map = HashMap::new();

        // 2.4 GHz band (band ID 0)
        band_map.insert(
            0,
            vec![
                2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447, 2452, 2457, 2462, 2467, 2472, 2484,
            ],
        );

        // 5 GHz band (band ID 1)
        band_map.insert(
            1,
            vec![
                5180, 5200, 5220, 5240, 5260, 5280, 5300, 5320, 5500, 5520, 5540, 5560, 5580, 5600,
                5620, 5640, 5660, 5680, 5700, 5745, 5765, 5785, 5805, 5825,
            ],
        );

        Some(band_map)
    }

    pub fn pretty_print(&self) -> String {
        let mac_str = self.mac.as_ref()
            .map(|mac| {
                if mac.len() >= 6 {
                    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
                } else {
                    "00:00:00:00:00:00".to_string()
                }
            })
            .unwrap_or_else(|| "00:00:00:00:00:00".to_string());

        format!(
            "Interface: {} (index: {:?}, phy: {:?}, MAC: {})",
            self.name_as_string(),
            self.index,
            self.phy,
            mac_str
        )
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(clippy::enum_variant_names)]
pub enum Band {
    Band2_4GHz,
    Band5GHz,
    Band6GHz,
    Band60GHz,
    Unknown,
}

#[cfg(target_os = "macos")]
impl std::fmt::Display for Band {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let band_str = match self {
            Band::Band2_4GHz => "2.4GHz",
            Band::Band5GHz => "5GHz",
            Band::Band6GHz => "6GHz",
            Band::Band60GHz => "60GHz",
            Band::Unknown => "Unknown",
        };
        write!(f, "{}", band_str)
    }
}

#[cfg(target_os = "macos")]
impl Band {
    #[allow(clippy::wrong_self_convention)]
    pub fn to_u8(&self) -> u8 {
        match self {
            Band::Band2_4GHz => 0,
            Band::Band5GHz => 1,
            Band::Band6GHz => 2,
            Band::Band60GHz => 3,
            Band::Unknown => 255,
        }
    }

    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Band::Band2_4GHz,
            1 => Band::Band5GHz,
            2 => Band::Band6GHz,
            3 => Band::Band60GHz,
            _ => Band::Unknown,
        }
    }

    // Constants for consistency with Linux
    pub const UNKNOWN: Band = Band::Unknown;
    pub const BAND_2_4_GHZ: Band = Band::Band2_4GHz;
    pub const BAND_5_GHZ: Band = Band::Band5GHz;
    pub const BAND_6_GHZ: Band = Band::Band6GHz;
    pub const BAND_60_GHZ: Band = Band::Band60GHz;
}

// Platform-specific implementations
#[cfg(target_os = "linux")]
pub fn get_interface_info(ifindex: i32) -> Result<Interface, String> {
    get_interface_info_idx(ifindex as u32).map_err(|e| e.to_string())
}

#[cfg(target_os = "macos")]
pub fn get_interface_info(ifindex: i32) -> Result<Interface, String> {
    crate::macos_interface::get_interface_info_macos(ifindex)
}

#[cfg(target_os = "linux")]
pub fn set_interface_channel(ifindex: i32, channel: u8, band: Band) -> Result<(), String> {
    set_interface_chan(ifindex as u32, channel as u32, band.to_u8()).map_err(|e| e.to_string())
}

#[cfg(target_os = "macos")]
pub fn set_interface_channel(ifindex: i32, channel: u8, _band: Band) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        use crate::airport;

        // Get interface name (simplified - should use proper index to name mapping)
        let ifname = if ifindex == 0 { "en0" } else { "en1" };

        // Set channel using airport utility
        airport::set_channel(ifname, channel)?;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
pub fn get_nl80211() -> Result<Nl80211, String> {
    Nl80211::new().map_err(|e| e.to_string())
}

#[cfg(target_os = "macos")]
pub fn get_nl80211() -> Result<Nl80211, String> {
    Nl80211Mock::new()
}

#[cfg(target_os = "macos")]
pub struct Nl80211Mock {
    // Mock structure for macOS
}

#[cfg(target_os = "macos")]
impl Nl80211Mock {
    pub fn new() -> Result<Self, String> {
        Ok(Self {})
    }

    pub fn get_interfaces(&self) -> Result<Vec<Interface>, String> {
        // Basic implementation to get network interfaces on macOS
        use std::process::Command;

        let output = Command::new("ifconfig")
            .arg("-l")
            .output()
            .map_err(|e| e.to_string())?;

        let interfaces_str = String::from_utf8_lossy(&output.stdout);
        let mut interfaces = Vec::new();

        for (idx, iface_name) in interfaces_str.split_whitespace().enumerate() {
            // Only include potential WiFi interfaces (en0, en1, etc.)
            if iface_name.starts_with("en") {
                interfaces.push(Interface {
                    index: Some(idx as u32),
                    ssid: None,
                    name: Some(iface_name.as_bytes().to_vec()),
                    mac: Some(vec![0, 0, 0, 0, 0, 0]), // Would need ioctl to get real MAC
                    frequency: Frequency::default(),
                    phy: Some(idx as u32),
                    phy_name: idx as u32,
                    device: Some(idx as u64),
                    current_iftype: Some(Nl80211Iftype::IftypeStation),
                    driver: Some("unknown".to_string()),
                });
            }
        }

        Ok(interfaces)
    }

    pub fn list_interfaces(&self) -> Result<Vec<Interface>, String> {
        self.get_interfaces()
    }

    pub fn list_phys(&self) -> Result<Vec<Phy>, String> {
        // Return a mock Phy for WiFi interfaces
        #[cfg(target_os = "macos")]
        {
            use crate::airport;

            let mut phys = Vec::new();

            // Check en0 (typically the main WiFi interface on macOS)
            if airport::check_monitor_capability("en0") {
                let active_monitor = crate::macos_monitor::is_interface_in_monitor_mode("en0");

                phys.push(Phy {
                    index: 0,
                    name: "phy0".to_string(),
                    iftypes: Some(vec![
                        Nl80211Iftype::IftypeStation,
                        Nl80211Iftype::IftypeMonitor,
                    ]),
                    active_monitor: Some(active_monitor),
                });
            }

            // Also check en1 if it exists
            if airport::check_monitor_capability("en1") {
                let active_monitor = crate::macos_monitor::is_interface_in_monitor_mode("en1");

                phys.push(Phy {
                    index: 1,
                    name: "phy1".to_string(),
                    iftypes: Some(vec![
                        Nl80211Iftype::IftypeStation,
                        Nl80211Iftype::IftypeMonitor,
                    ]),
                    active_monitor: Some(active_monitor),
                });
            }

            Ok(phys)
        }

        #[cfg(not(target_os = "macos"))]
        Ok(Vec::new())
    }

    fn get_interface_name_from_index(&self, ifindex: i32) -> Result<String, String> {
        // Get interface name from index
        // This is a simplified version - in production you'd use if_indextoname
        let interfaces = self.get_interfaces()?;

        for iface in interfaces {
            if iface.index == Some(ifindex as u32) {
                return Ok(iface.name_as_string());
            }
        }

        // Default to en0 if not found
        Ok("en0".to_string())
    }

    pub fn set_interface_down(&self, ifindex: i32) -> Result<(), String> {
        // Use ioctl to bring interface down
        use libc::{ioctl, socket, AF_INET, IFF_UP, SOCK_DGRAM};
        use std::ffi::CString;
        use std::mem;

        // ioctl constants for macOS
        const SIOCSIFFLAGS: libc::c_ulong = 0x80206910;
        const SIOCGIFFLAGS: libc::c_ulong = 0xc0206911;

        unsafe {
            let sock = socket(AF_INET, SOCK_DGRAM, 0);
            if sock < 0 {
                return Err("Failed to create socket".to_string());
            }

            // Get interface name
            let ifname = self.get_interface_name_from_index(ifindex)?;
            let ifname_cstr = CString::new(ifname.clone()).map_err(|e| e.to_string())?;

            // Create ifreq structure
            let mut ifr: libc::ifreq = mem::zeroed();
            let name_bytes = ifname_cstr.as_bytes_with_nul();
            if name_bytes.len() > ifr.ifr_name.len() {
                libc::close(sock);
                return Err("Interface name too long".to_string());
            }

            for (i, &byte) in name_bytes.iter().enumerate() {
                ifr.ifr_name[i] = byte as libc::c_char;
            }

            // Get current flags
            if ioctl(sock, SIOCGIFFLAGS as _, &mut ifr) < 0 {
                libc::close(sock);
                return Err("Failed to get interface flags".to_string());
            }

            // Clear the UP flag
            ifr.ifr_ifru.ifru_flags &= !(IFF_UP as i16);

            // Set the new flags
            if ioctl(sock, SIOCSIFFLAGS as _, &ifr) < 0 {
                libc::close(sock);
                return Err("Failed to set interface down".to_string());
            }

            libc::close(sock);
        }

        Ok(())
    }

    pub fn set_interface_up(&self, ifindex: i32) -> Result<(), String> {
        // Use ioctl to bring interface up
        use libc::{ioctl, socket, AF_INET, IFF_UP, SOCK_DGRAM};
        use std::ffi::CString;
        use std::mem;

        // ioctl constants for macOS
        const SIOCSIFFLAGS: libc::c_ulong = 0x80206910;
        const SIOCGIFFLAGS: libc::c_ulong = 0xc0206911;

        unsafe {
            let sock = socket(AF_INET, SOCK_DGRAM, 0);
            if sock < 0 {
                return Err("Failed to create socket".to_string());
            }

            // Get interface name
            let ifname = self.get_interface_name_from_index(ifindex)?;
            let ifname_cstr = CString::new(ifname.clone()).map_err(|e| e.to_string())?;

            // Create ifreq structure
            let mut ifr: libc::ifreq = mem::zeroed();
            let name_bytes = ifname_cstr.as_bytes_with_nul();
            if name_bytes.len() > ifr.ifr_name.len() {
                libc::close(sock);
                return Err("Interface name too long".to_string());
            }

            for (i, &byte) in name_bytes.iter().enumerate() {
                ifr.ifr_name[i] = byte as libc::c_char;
            }

            // Get current flags
            if ioctl(sock, SIOCGIFFLAGS as _, &mut ifr) < 0 {
                libc::close(sock);
                return Err("Failed to get interface flags".to_string());
            }

            // Set the UP flag
            ifr.ifr_ifru.ifru_flags |= IFF_UP as i16;

            // Set the new flags
            if ioctl(sock, SIOCSIFFLAGS as _, &ifr) < 0 {
                libc::close(sock);
                return Err("Failed to set interface up".to_string());
            }

            libc::close(sock);
        }

        Ok(())
    }

    pub fn set_interface_mac(&self, ifindex: i32, mac: &[u8; 6]) -> Result<(), String> {
        crate::macos_interface::set_interface_mac_macos(ifindex, mac)
    }

    pub fn set_interface_monitor(&self, active: bool, ifindex: i32) -> Result<(), String> {
        #[cfg(target_os = "macos")]
        {
            use crate::airport;

            // Get interface name
            let ifname = self.get_interface_name_from_index(ifindex)?;

            if active {
                // Enable monitor mode using airport utility
                airport::enable_monitor_mode(&ifname)?;
            } else {
                // Disable monitor mode
                airport::disable_monitor_mode(&ifname)?;
            }

            Ok(())
        }

        #[cfg(not(target_os = "macos"))]
        {
            Err("Monitor mode not implemented for this platform".to_string())
        }
    }

    pub fn set_powersave_off(&self, ifindex: i32) -> Result<(), String> {
        crate::macos_interface::set_powersave_off_macos(ifindex)
    }

    pub fn set_interface_station(&self, ifindex: i32) -> Result<(), String> {
        crate::macos_interface::set_interface_station_macos(ifindex)
    }

    pub fn set_interface_channel(
        &self,
        ifindex: i32,
        channel: u8,
        band: Band,
    ) -> Result<(), String> {
        set_interface_channel(ifindex, channel, band)
    }
}

#[cfg(target_os = "macos")]
pub type Nl80211 = Nl80211Mock;

#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
pub struct Phy {
    pub index: i32,
    pub name: String,
    pub iftypes: Option<Vec<Nl80211Iftype>>,
    pub active_monitor: Option<bool>,
}

// Note: nl80211_ng::Phy doesn't exist in the current version

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Nl80211Iftype {
    IftypeUnspecified,
    IftypeAdhoc,
    IftypeStation,
    IftypeAp,
    IftypeApVlan,
    IftypeWds,
    IftypeMonitor,
    IftypeMeshPoint,
    IftypeP2pClient,
    IftypeP2pGo,
    IftypeP2pDevice,
    IftypeOcb,
    IftypeNan,
}

// Channel/frequency conversion functions
#[cfg(target_os = "linux")]
pub fn frequency_to_band(freq: u32) -> Option<Band> {
    Some(Band::from(freq_to_band(freq)))
}

#[cfg(target_os = "macos")]
pub fn frequency_to_band(freq: u32) -> Option<Band> {
    if (2412..=2484).contains(&freq) {
        Some(Band::Band2_4GHz)
    } else if (5180..=5825).contains(&freq) {
        Some(Band::Band5GHz)
    } else if (5945..=7125).contains(&freq) {
        Some(Band::Band6GHz)
    } else if (58320..=64800).contains(&freq) {
        Some(Band::Band60GHz)
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
pub fn map_channel_to_band(channel_str: &str) -> Option<(u8, Band)> {
    map_str_to_band_and_channel(channel_str)
        .map(|(band, channel)| (channel as u8, Band::from(band)))
}

#[cfg(target_os = "macos")]
pub fn map_channel_to_band(channel_str: &str) -> Option<(u8, Band)> {
    let channel: u8 = channel_str.parse().ok()?;

    // Basic channel to band mapping
    if (1..=14).contains(&channel) {
        Some((channel, Band::Band2_4GHz))
    } else if (36..=165).contains(&channel) {
        Some((channel, Band::Band5GHz))
    } else if (1..=233).contains(&channel) {
        // 6GHz channels
        Some((channel, Band::Band6GHz))
    } else {
        None
    }
}
