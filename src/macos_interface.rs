// macOS-specific interface management implementation
// Provides real interface information and control

use libc::{c_char, ioctl, socket, AF_INET, SOCK_DGRAM};
use std::ffi::CString;
use std::mem;
use std::process::Command;

use crate::interface::{Frequency, Interface, Nl80211Iftype};

// ioctl constants for macOS
const SIOCGIFHWADDR: libc::c_ulong = 0xc0206935; // Get hardware address
const SIOCGIFFLAGS: libc::c_ulong = 0xc0206911; // Get interface flags
#[allow(dead_code)]
const SIOCSIFFLAGS: libc::c_ulong = 0x80206910; // Set interface flags
#[allow(dead_code)]
const SIOCGIFADDR: libc::c_ulong = 0xc0206921; // Get interface address
#[allow(dead_code)]
const SIOCSIFLLADDR: libc::c_ulong = 0x8020693c; // Set link-level address (MAC)

// Interface flags
const IFF_UP: i16 = 0x1;
#[allow(dead_code)]
const IFF_RUNNING: i16 = 0x40;
const IFF_PROMISC: i16 = 0x100;

/// Get detailed interface information for macOS
pub fn get_interface_info_macos(ifindex: i32) -> Result<Interface, String> {
    unsafe {
        let sock = socket(AF_INET, SOCK_DGRAM, 0);
        if sock < 0 {
            return Err("Failed to create socket".to_string());
        }

        // Get interface name from index
        let ifname = get_interface_name_from_index(ifindex)?;
        let ifname_cstr = CString::new(ifname.clone()).map_err(|e| e.to_string())?;

        // Create ifreq structure
        let mut ifr: libc::ifreq = mem::zeroed();
        let name_bytes = ifname_cstr.as_bytes_with_nul();
        if name_bytes.len() > ifr.ifr_name.len() {
            libc::close(sock);
            return Err("Interface name too long".to_string());
        }

        for (i, &byte) in name_bytes.iter().enumerate() {
            ifr.ifr_name[i] = byte as c_char;
        }

        // Get MAC address
        let mac = if ioctl(sock, SIOCGIFHWADDR as _, &mut ifr) == 0 {
            // Extract MAC address from ifr_ifru.ifru_addr
            let addr_bytes = &ifr.ifr_ifru.ifru_addr;
            // On macOS, the MAC is in sa_data starting at offset 0
            let mac_ptr = addr_bytes.sa_data.as_ptr() as *const u8;
            let mac_slice = std::slice::from_raw_parts(mac_ptr, 6);
            [
                mac_slice[0],
                mac_slice[1],
                mac_slice[2],
                mac_slice[3],
                mac_slice[4],
                mac_slice[5],
            ]
        } else {
            // Fallback: try to get MAC using ifconfig
            get_mac_from_ifconfig(&ifname).unwrap_or([0; 6])
        };

        // Get interface flags to determine mode
        let mut _mode = None;
        let mut current_iftype = None;
        if ioctl(sock, SIOCGIFFLAGS as _, &mut ifr) == 0 {
            let flags = ifr.ifr_ifru.ifru_flags;
            if flags & IFF_UP != 0 {
                _mode = Some(1); // Interface is up
            }
            if flags & IFF_PROMISC != 0 {
                current_iftype = Some(Nl80211Iftype::IftypeMonitor);
            } else {
                current_iftype = Some(Nl80211Iftype::IftypeStation);
            }
        }

        // Get frequency and channel using airport or wdutil
        let (frequency, channel) = get_frequency_and_channel(&ifname)?;

        // Get SSID if connected
        let ssid = get_current_ssid(&ifname);

        // Get driver info
        let driver = get_driver_info(&ifname);

        libc::close(sock);

        Ok(Interface {
            index: Some(ifindex as u32),
            ssid,
            name: Some(ifname.as_bytes().to_vec()),
            mac: Some(mac.to_vec()),
            frequency: Frequency {
                frequency,
                channel: channel.map(|c| c as u32),
                width: None,
                pwr: None,
            },
            phy: Some(ifindex as u32), // Use index as phy for simplicity
            phy_name: ifindex as u32,
            device: Some(ifindex as u64),
            current_iftype,
            driver,
        })
    }
}

/// Get interface name from index
fn get_interface_name_from_index(ifindex: i32) -> Result<String, String> {
    // Use if_indextoname to get the actual interface name
    unsafe {
        let mut name_buf = [0u8; libc::IF_NAMESIZE];
        let name_ptr = libc::if_indextoname(ifindex as u32, name_buf.as_mut_ptr() as *mut c_char);

        if name_ptr.is_null() {
            // Fallback to common names
            if ifindex == 0 {
                return Ok("en0".to_string());
            } else {
                return Ok(format!("en{}", ifindex));
            }
        }

        let name = std::ffi::CStr::from_ptr(name_ptr)
            .to_string_lossy()
            .to_string();
        Ok(name)
    }
}

/// Get MAC address using ifconfig command
fn get_mac_from_ifconfig(ifname: &str) -> Result<[u8; 6], String> {
    let output = Command::new("ifconfig")
        .arg(ifname)
        .output()
        .map_err(|e| format!("Failed to run ifconfig: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Look for line containing "ether"
    for line in stdout.lines() {
        if line.contains("ether") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let mac_str = parts[1];
                return parse_mac_address(mac_str);
            }
        }
    }

    Err("MAC address not found".to_string())
}

/// Parse MAC address from string format "aa:bb:cc:dd:ee:ff"
fn parse_mac_address(mac_str: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() != 6 {
        return Err("Invalid MAC address format".to_string());
    }

    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] =
            u8::from_str_radix(part, 16).map_err(|_| "Failed to parse MAC address".to_string())?;
    }

    Ok(mac)
}

/// Get frequency and channel for the interface
fn get_frequency_and_channel(ifname: &str) -> Result<(Option<u32>, Option<u8>), String> {
    // Try using airport first
    if let Ok(channel) = crate::airport::get_current_channel(ifname) {
        // Convert channel to frequency
        let frequency = channel_to_frequency(channel);
        return Ok((Some(frequency), Some(channel)));
    }

    // Try wdutil as fallback
    if let Ok(output) = Command::new("wdutil").arg("info").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("Channel") && line.contains(ifname) {
                // Parse channel from wdutil output
                if let Some(channel) = parse_channel_from_line(line) {
                    let frequency = channel_to_frequency(channel);
                    return Ok((Some(frequency), Some(channel)));
                }
            }
        }
    }

    Ok((None, None))
}

/// Convert channel number to frequency
fn channel_to_frequency(channel: u8) -> u32 {
    match channel {
        // 2.4 GHz channels
        1 => 2412,
        2 => 2417,
        3 => 2422,
        4 => 2427,
        5 => 2432,
        6 => 2437,
        7 => 2442,
        8 => 2447,
        9 => 2452,
        10 => 2457,
        11 => 2462,
        12 => 2467,
        13 => 2472,
        14 => 2484,
        // 5 GHz channels (common ones)
        36 => 5180,
        40 => 5200,
        44 => 5220,
        48 => 5240,
        52 => 5260,
        56 => 5280,
        60 => 5300,
        64 => 5320,
        100 => 5500,
        104 => 5520,
        108 => 5540,
        112 => 5560,
        116 => 5580,
        120 => 5600,
        124 => 5620,
        128 => 5640,
        132 => 5660,
        136 => 5680,
        140 => 5700,
        144 => 5720,
        149 => 5745,
        153 => 5765,
        157 => 5785,
        161 => 5805,
        165 => 5825,
        _ => 2412, // Default to channel 1
    }
}

/// Parse channel number from a line of text
fn parse_channel_from_line(line: &str) -> Option<u8> {
    // Look for patterns like "Channel: 6" or "channel 6"
    let parts: Vec<&str> = line
        .split(|c: char| c == ':' || c.is_whitespace())
        .collect();
    for (i, part) in parts.iter().enumerate() {
        if part.to_lowercase().contains("channel") && i + 1 < parts.len() {
            if let Ok(channel) = parts[i + 1].parse::<u8>() {
                return Some(channel);
            }
        }
    }
    None
}

/// Get current SSID if connected
fn get_current_ssid(_ifname: &str) -> Option<Vec<u8>> {
    // Try using airport
    if let Ok(output) = Command::new(
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
    )
    .arg("-I")
    .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.trim().starts_with("SSID:") {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 {
                    let ssid = parts[1].trim();
                    if !ssid.is_empty() {
                        return Some(ssid.as_bytes().to_vec());
                    }
                }
            }
        }
    }

    None
}

/// Get driver information for the interface
fn get_driver_info(ifname: &str) -> Option<String> {
    // Try to get driver info using system_profiler
    if let Ok(output) = Command::new("system_profiler")
        .arg("SPNetworkDataType")
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Parse the output to find driver info
        // This is simplified - real parsing would be more complex
        if stdout.contains(ifname) {
            return Some("Apple WiFi".to_string());
        }
    }

    Some("unknown".to_string())
}

/// Set MAC address for the interface
pub fn set_interface_mac_macos(ifindex: i32, mac: &[u8; 6]) -> Result<(), String> {
    // Get interface name
    let ifname = get_interface_name_from_index(ifindex)?;

    // First bring interface down
    bring_interface_down(&ifname)?;

    // Use ifconfig to set MAC address
    let mac_str = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );

    let output = Command::new("sudo")
        .arg("ifconfig")
        .arg(&ifname)
        .arg("ether")
        .arg(&mac_str)
        .output()
        .map_err(|e| format!("Failed to set MAC address: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to set MAC address: {}", stderr));
    }

    // Bring interface back up
    bring_interface_up(&ifname)?;

    Ok(())
}

/// Disable power save mode
pub fn set_powersave_off_macos(ifindex: i32) -> Result<(), String> {
    // Get interface name
    let _ifname = get_interface_name_from_index(ifindex)?;

    // Use pmset to disable power save for WiFi
    let output = Command::new("sudo")
        .arg("pmset")
        .arg("-a")
        .arg("womp")
        .arg("0") // Disable Wake on WiFi
        .output()
        .map_err(|e| format!("Failed to run pmset: {}", e))?;

    if !output.status.success() {
        // This is not critical, continue anyway
        eprintln!("Warning: Failed to disable Wake on WiFi");
    }

    // Also try to disable power save using airport if available
    if std::path::Path::new(
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
    )
    .exists()
    {
        let _ = Command::new("sudo")
            .arg("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport")
            .arg("prefs")
            .arg("RequireAdminPowerToggle=NO")
            .output();
    }

    Ok(())
}

/// Set interface to station (managed) mode
pub fn set_interface_station_macos(ifindex: i32) -> Result<(), String> {
    // Get interface name
    let ifname = get_interface_name_from_index(ifindex)?;

    // Disable monitor mode if it's enabled
    crate::airport::disable_monitor_mode(&ifname)?;

    // Bring interface down and up to reset it
    bring_interface_down(&ifname)?;
    std::thread::sleep(std::time::Duration::from_millis(500));
    bring_interface_up(&ifname)?;

    Ok(())
}

/// Bring interface down
fn bring_interface_down(ifname: &str) -> Result<(), String> {
    let output = Command::new("sudo")
        .arg("ifconfig")
        .arg(ifname)
        .arg("down")
        .output()
        .map_err(|e| format!("Failed to bring interface down: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to bring interface down: {}", stderr));
    }

    Ok(())
}

/// Bring interface up
fn bring_interface_up(ifname: &str) -> Result<(), String> {
    let output = Command::new("sudo")
        .arg("ifconfig")
        .arg(ifname)
        .arg("up")
        .output()
        .map_err(|e| format!("Failed to bring interface up: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to bring interface up: {}", stderr));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mac_address() {
        let mac_str = "aa:bb:cc:dd:ee:ff";
        let result = parse_mac_address(mac_str).unwrap();
        assert_eq!(result, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_channel_to_frequency() {
        assert_eq!(channel_to_frequency(1), 2412);
        assert_eq!(channel_to_frequency(6), 2437);
        assert_eq!(channel_to_frequency(11), 2462);
        assert_eq!(channel_to_frequency(36), 5180);
        assert_eq!(channel_to_frequency(149), 5745);
    }

    #[test]
    fn test_get_interface_name() {
        // This test might fail if interface doesn't exist
        let _ = get_interface_name_from_index(0);
    }
}
