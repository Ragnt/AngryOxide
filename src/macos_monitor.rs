// Enhanced monitor mode detection and management for macOS
// Provides accurate active monitor detection and hardware capability checks

use std::fs;
use std::path::Path;
use std::process::Command;

/// Check if an interface is actively in monitor mode
pub fn is_interface_in_monitor_mode(ifname: &str) -> bool {
    // Check multiple indicators to determine if monitor mode is active

    // 1. Check if tcpdump is running with monitor flag on this interface
    if is_tcpdump_monitoring(ifname) {
        return true;
    }

    // 2. Check if airport sniff is running
    if is_airport_sniffing(ifname) {
        return true;
    }

    // 3. Check interface flags for promiscuous mode
    if is_interface_promiscuous(ifname) {
        // Promiscuous mode often indicates monitor mode
        return true;
    }

    // 4. Check if we can read radiotap headers (definitive test)
    if can_read_radiotap_headers(ifname) {
        return true;
    }

    false
}

/// Check if tcpdump is running in monitor mode on the interface
fn is_tcpdump_monitoring(ifname: &str) -> bool {
    // Use ps to check for tcpdump processes
    if let Ok(output) = Command::new("ps").arg("aux").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Look for tcpdump with -I flag (monitor mode) on our interface
        let _search_pattern = format!("tcpdump.*-I.*{}", ifname);
        for line in stdout.lines() {
            if line.contains("tcpdump") && line.contains("-I") && line.contains(ifname) {
                return true;
            }
        }
    }

    false
}

/// Check if airport is running in sniff mode
fn is_airport_sniffing(ifname: &str) -> bool {
    // Check for airport sniff process
    if let Ok(output) = Command::new("ps").arg("aux").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Look for airport sniff command
        let _search_pattern = format!("airport.*{}.*sniff", ifname);
        for line in stdout.lines() {
            if line.contains("airport") && line.contains(ifname) && line.contains("sniff") {
                return true;
            }
        }
    }

    // Also check for pcap files in /tmp/ which airport creates
    if let Ok(entries) = fs::read_dir("/tmp") {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(filename) = path.file_name() {
                let filename_str = filename.to_string_lossy();
                if filename_str.starts_with("airportSniff") && filename_str.ends_with(".cap") {
                    // Check if file was modified recently (within last minute)
                    if let Ok(metadata) = fs::metadata(&path) {
                        if let Ok(modified) = metadata.modified() {
                            if let Ok(elapsed) = modified.elapsed() {
                                if elapsed.as_secs() < 60 {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    false
}

/// Check if interface is in promiscuous mode
fn is_interface_promiscuous(ifname: &str) -> bool {
    if let Ok(output) = Command::new("ifconfig").arg(ifname).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Look for PROMISC flag
        stdout.contains("PROMISC")
    } else {
        false
    }
}

/// Test if we can actually read radiotap headers from the interface
fn can_read_radiotap_headers(ifname: &str) -> bool {
    // Try to capture a packet and check for radiotap header
    // This is the most definitive test but requires actual packet capture

    // Use tcpdump to capture one packet and check the link type
    if let Ok(output) = Command::new("tcpdump")
        .arg("-i")
        .arg(ifname)
        .arg("-I") // Try monitor mode
        .arg("-c")
        .arg("1") // Capture just one packet
        .arg("-w")
        .arg("-") // Write to stdout
        .arg("2>&1")
        .output()
    {
        // Check if output contains radiotap or 802.11
        let output_str = String::from_utf8_lossy(&output.stdout);
        let error_str = String::from_utf8_lossy(&output.stderr);

        // If we can capture with -I flag without error, monitor mode works
        if output.status.success() || output_str.contains("802.11") || error_str.contains("802.11")
        {
            return true;
        }
    }

    false
}

/// Get detailed hardware capabilities for WiFi interface
pub fn get_hardware_capabilities(ifname: &str) -> HardwareCapabilities {
    HardwareCapabilities {
        chipset: get_chipset_info(ifname),
        supports_monitor: check_monitor_support(ifname),
        supports_injection: check_injection_support(ifname),
        supported_bands: get_supported_bands(ifname),
        supported_channels: get_supported_channels(ifname),
        supports_active_monitor: check_active_monitor_support(ifname),
    }
}

/// Hardware capability information
#[derive(Debug, Default, Clone)]
pub struct HardwareCapabilities {
    pub chipset: String,
    pub supports_monitor: bool,
    pub supports_injection: bool,
    pub supports_active_monitor: bool,
    pub supported_bands: Vec<String>,
    pub supported_channels: Vec<u8>,
}

/// Get chipset information
fn get_chipset_info(_ifname: &str) -> String {
    // Use system_profiler to get WiFi hardware info
    if let Ok(output) = Command::new("system_profiler")
        .arg("SPAirPortDataType")
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse for chipset info
        for line in stdout.lines() {
            if line.contains("Card Type:") || line.contains("Wireless Card Type:") {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 {
                    return parts[1].trim().to_string();
                }
            }
        }

        // Try to identify by looking for known patterns
        if stdout.contains("Broadcom") {
            return "Broadcom BCM43xx".to_string();
        } else if stdout.contains("AirPort Extreme") {
            return "Apple AirPort Extreme".to_string();
        }
    }

    // Try ioreg as fallback
    if let Ok(output) = Command::new("ioreg")
        .arg("-l")
        .arg("-n")
        .arg("AirPort_BrcmNIC")
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.is_empty() {
            return "Broadcom AirPort".to_string();
        }
    }

    "Unknown".to_string()
}

/// Check if monitor mode is supported
fn check_monitor_support(ifname: &str) -> bool {
    // Check if we can enable monitor mode

    // 1. Check if airport exists and works
    if Path::new(
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
    )
    .exists()
    {
        if let Ok(output) = Command::new("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport")
            .arg("-I")
            .output()
        {
            if output.status.success() {
                return true;
            }
        }
    }

    // 2. Check if tcpdump supports monitor mode
    if let Ok(output) = Command::new("tcpdump")
        .arg("-D") // List interfaces
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains(ifname) {
            // Try to actually enable monitor mode (dry run)
            if let Ok(test_output) = Command::new("tcpdump")
                .arg("-i")
                .arg(ifname)
                .arg("-I")
                .arg("-c")
                .arg("0") // Don't capture, just test
                .output()
            {
                // If no permission error, monitor mode is likely supported
                let stderr = String::from_utf8_lossy(&test_output.stderr);
                if !stderr.contains("Operation not permitted")
                    && !stderr.contains("You don't have permission")
                {
                    return true;
                }
            }
        }
    }

    false
}

/// Check if packet injection is supported
fn check_injection_support(ifname: &str) -> bool {
    // Injection support depends on chipset and driver
    let chipset = get_chipset_info(ifname);

    // Known chipsets with injection support
    if chipset.contains("Broadcom") {
        // Older Broadcom chips support injection
        return true;
    }

    // Apple Silicon Macs generally don't support injection
    if is_apple_silicon() {
        return false;
    }

    // Intel Macs with certain chipsets support injection
    true
}

/// Check if running on Apple Silicon
fn is_apple_silicon() -> bool {
    if let Ok(output) = Command::new("uname").arg("-m").output() {
        let arch = String::from_utf8_lossy(&output.stdout);
        return arch.contains("arm64") || arch.contains("aarch64");
    }
    false
}

/// Check for active monitor support (monitor mode while associated)
fn check_active_monitor_support(_ifname: &str) -> bool {
    // macOS generally doesn't support active monitor
    // (can't be in monitor mode and associated simultaneously)
    false
}

/// Get supported WiFi bands
fn get_supported_bands(_ifname: &str) -> Vec<String> {
    let mut bands = Vec::new();

    // Use system_profiler to get supported PHY modes
    if let Ok(output) = Command::new("system_profiler")
        .arg("SPAirPortDataType")
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Check for band support indicators
        if stdout.contains("802.11a")
            || stdout.contains("802.11n")
            || stdout.contains("802.11ac")
            || stdout.contains("802.11ax")
        {
            bands.push("5GHz".to_string());
        }

        if stdout.contains("802.11b") || stdout.contains("802.11g") || stdout.contains("802.11n") {
            bands.push("2.4GHz".to_string());
        }

        if stdout.contains("802.11ax") || stdout.contains("Wi-Fi 6E") {
            bands.push("6GHz".to_string());
        }
    }

    // Default to common bands if we can't detect
    if bands.is_empty() {
        bands.push("2.4GHz".to_string());
        bands.push("5GHz".to_string());
    }

    bands
}

/// Get supported channels
fn get_supported_channels(_ifname: &str) -> Vec<u8> {
    let mut channels = Vec::new();

    // Get country code to determine allowed channels
    let country_code = get_country_code();

    // Add 2.4GHz channels
    channels.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);

    // Add 12, 13 for non-US
    if country_code != "US" {
        channels.extend_from_slice(&[12, 13]);
    }

    // Add 14 for Japan
    if country_code == "JP" {
        channels.push(14);
    }

    // Add common 5GHz channels
    channels.extend_from_slice(&[
        36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
        149, 153, 157, 161, 165,
    ]);

    channels
}

/// Get WiFi country code
fn get_country_code() -> String {
    if let Ok(output) = Command::new(
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
    )
    .arg("prefs")
    .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("Country Code") {
                let parts: Vec<&str> = line.split('=').collect();
                if parts.len() >= 2 {
                    return parts[1].trim().to_string();
                }
            }
        }
    }

    // Default to US
    "US".to_string()
}

/// Update Phy structure with actual active monitor detection
pub fn update_phy_active_monitor(phy: &mut crate::interface::Phy, ifname: &str) {
    phy.active_monitor = Some(is_interface_in_monitor_mode(ifname));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitor_detection() {
        // Test with common interface name
        let _is_monitor = is_interface_in_monitor_mode("en0");
        // We don't assert here as it depends on system state
    }

    #[test]
    fn test_hardware_capabilities() {
        let caps = get_hardware_capabilities("en0");
        println!("Hardware capabilities: {:?}", caps);
        assert!(!caps.chipset.is_empty());
    }

    #[test]
    fn test_apple_silicon_detection() {
        let is_m1 = is_apple_silicon();
        println!("Is Apple Silicon: {}", is_m1);
    }
}
