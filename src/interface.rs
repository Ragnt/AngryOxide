// Platform abstraction layer for wireless interface operations

use std::collections::HashMap;

#[cfg(target_os = "linux")]
use nl80211_ng::{
    attr::Nl80211Iftype,
    channels::{freq_to_band, map_str_to_band_and_channel, WiFiBand},
    get_interface_info_idx, set_interface_chan, Nl80211,
};

// Re-export common types that are used throughout the codebase
#[cfg(target_os = "linux")]
pub use nl80211_ng::{channels::WiFiBand};

// Create an extension trait for Interface on Linux
#[cfg(target_os = "linux")]
pub trait InterfaceExt {
    fn name_as_string(&self) -> String;
    fn driver_as_string(&self) -> String;
}

#[cfg(target_os = "linux")]
impl InterfaceExt for nl80211_ng::Interface {
    fn name_as_string(&self) -> String {
        self.name.clone()
    }
    
    fn driver_as_string(&self) -> String {
        self.driver.clone().unwrap_or_else(|| "unknown".to_string())
    }
}

#[cfg(target_os = "linux")]
pub use nl80211_ng::Interface;

// Create a wrapper type for Band to add the to_u8() method
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Band(WiFiBand);

#[cfg(target_os = "linux")]
impl Band {
    pub fn to_u8(&self) -> u8 {
        match self.0 {
            WiFiBand::Band2_4GHz => 0,
            WiFiBand::Band5GHz => 1,
            WiFiBand::Band6GHz => 2,
            WiFiBand::Band60GHz => 3,
            _ => 255, // Handle any unknown bands
        }
    }
    
    pub fn to_string(&self) -> String {
        format!("{:?}", self.0)
    }
    
    pub const Unknown: Band = Band(WiFiBand::Band2_4GHz); // Placeholder for Unknown
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

// For macOS, we need to define compatible types
#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
pub struct Interface {
    pub index: Option<i32>,
    pub ssid: Option<String>,
    pub name: String,
    pub mac: [u8; 6],
    pub frequency: Option<u32>,
    pub channel: Option<u8>,
    pub phy: i32,
    pub device: Option<u32>,
    pub wdev: Option<u64>,
    pub mode: Option<u32>,
    pub current_iftype: Option<u32>,
}

#[cfg(target_os = "macos")]
impl Interface {
    pub fn name_as_string(&self) -> String {
        self.name.clone()
    }
    
    pub fn driver_as_string(&self) -> String {
        "unknown".to_string() // macOS doesn't expose driver info easily
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Band {
    Band2_4GHz,
    Band5GHz,
    Band6GHz,
    Band60GHz,
    Unknown,
}

#[cfg(target_os = "macos")]
impl Band {
    pub fn to_string(&self) -> String {
        match self {
            Band::Band2_4GHz => "2.4GHz",
            Band::Band5GHz => "5GHz",
            Band::Band6GHz => "6GHz",
            Band::Band60GHz => "60GHz",
            Band::Unknown => "Unknown",
        }.to_string()
    }
    
    pub fn to_u8(&self) -> u8 {
        match self {
            Band::Band2_4GHz => 0,
            Band::Band5GHz => 1,
            Band::Band6GHz => 2,
            Band::Band60GHz => 3,
            Band::Unknown => 255,
        }
    }
}

// Platform-specific implementations
#[cfg(target_os = "linux")]
pub fn get_interface_info(ifindex: i32) -> Result<Interface, String> {
    get_interface_info_idx(ifindex).map_err(|e| e.to_string())
}

#[cfg(target_os = "macos")]
pub fn get_interface_info(ifindex: i32) -> Result<Interface, String> {
    // Placeholder implementation for macOS
    // Would need to use IOKit or similar macOS APIs
    Err("macOS interface info not yet implemented".to_string())
}

#[cfg(target_os = "linux")]
pub fn set_interface_channel(ifindex: i32, channel: u8, band: Band) -> Result<(), String> {
    set_interface_chan(ifindex, channel, band.into()).map_err(|e| e.to_string())
}

#[cfg(target_os = "macos")]
pub fn set_interface_channel(ifindex: i32, channel: u8, band: Band) -> Result<(), String> {
    // Placeholder implementation for macOS
    Err("macOS channel setting not yet implemented".to_string())
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
    
    pub fn list_interfaces(&self) -> Result<Vec<Interface>, String> {
        // Placeholder - would need to enumerate network interfaces on macOS
        Ok(Vec::new())
    }
    
    pub fn list_phys(&self) -> Result<Vec<Phy>, String> {
        Ok(Vec::new())
    }
    
    pub fn set_interface_down(&self, _ifindex: i32) -> Result<(), String> {
        Err("macOS set_interface_down not yet implemented".to_string())
    }
    
    pub fn set_interface_up(&self, _ifindex: i32) -> Result<(), String> {
        Err("macOS set_interface_up not yet implemented".to_string())
    }
    
    pub fn set_interface_mac(&self, _ifindex: i32, _mac: &[u8; 6]) -> Result<(), String> {
        Err("macOS set_interface_mac not yet implemented".to_string())
    }
    
    pub fn set_interface_monitor(&self, _active: bool, _ifindex: i32) -> Result<(), String> {
        Err("macOS set_interface_monitor not yet implemented".to_string())
    }
    
    pub fn set_powersave_off(&self, _ifindex: i32) -> Result<(), String> {
        Err("macOS set_powersave_off not yet implemented".to_string())
    }
    
    pub fn set_interface_station(&self, _ifindex: i32) -> Result<(), String> {
        Err("macOS set_interface_station not yet implemented".to_string())
    }
    
    pub fn set_interface_channel(&self, ifindex: i32, channel: u8, band: Band) -> Result<(), String> {
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
}

#[cfg(target_os = "linux")]
pub use nl80211_ng::Phy;

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

#[cfg(target_os = "linux")]
pub use nl80211_ng::attr::Nl80211Iftype;

// Channel/frequency conversion functions
#[cfg(target_os = "linux")]
pub fn frequency_to_band(freq: u32) -> Option<Band> {
    freq_to_band(freq).map(Band::from)
}

#[cfg(target_os = "macos")]
pub fn frequency_to_band(freq: u32) -> Option<Band> {
    if freq >= 2412 && freq <= 2484 {
        Some(Band::Band2_4GHz)
    } else if freq >= 5180 && freq <= 5825 {
        Some(Band::Band5GHz)
    } else if freq >= 5945 && freq <= 7125 {
        Some(Band::Band6GHz)
    } else if freq >= 58320 && freq <= 64800 {
        Some(Band::Band60GHz)
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
pub fn map_channel_to_band(channel_str: &str) -> Option<(u8, Band)> {
    map_str_to_band_and_channel(channel_str).map(|(band, channel)| (channel, Band::from(band)))
}

#[cfg(target_os = "macos")]
pub fn map_channel_to_band(channel_str: &str) -> Option<(u8, Band)> {
    let channel: u8 = channel_str.parse().ok()?;
    
    // Basic channel to band mapping
    if channel >= 1 && channel <= 14 {
        Some((channel, Band::Band2_4GHz))
    } else if channel >= 36 && channel <= 165 {
        Some((channel, Band::Band5GHz))
    } else if channel >= 1 && channel <= 233 {
        // 6GHz channels
        Some((channel, Band::Band6GHz))
    } else {
        None
    }
}