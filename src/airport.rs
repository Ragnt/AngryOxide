// WiFi control wrapper for macOS
// This module provides functions for monitor mode and channel control
// Supports multiple methods: airport (legacy but still works), tcpdump (modern), and wdutil (info)

#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

/// Path to the Airport utility on macOS
#[cfg(target_os = "macos")]
const AIRPORT_PATH: &str =
    "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport";

/// Path to tcpdump (available on all macOS versions)
#[cfg(target_os = "macos")]
const TCPDUMP_PATH: &str = "/usr/sbin/tcpdump";

/// Path to wdutil (Wireless Diagnostics utility)
#[cfg(target_os = "macos")]
const WDUTIL_PATH: &str = "/usr/bin/wdutil";

/// Disassociate from the current WiFi network
#[cfg(target_os = "macos")]
pub fn disassociate() -> Result<(), String> {
    use std::path::Path;

    // Try airport first if available
    if Path::new(AIRPORT_PATH).exists() {
        let output = Command::new(AIRPORT_PATH).arg("-z").output();

        if let Ok(output) = output {
            if output.status.success() {
                return Ok(());
            }
        }
    }

    // Fallback: bring interface down and up to force disassociation
    let _ = Command::new("/sbin/ifconfig")
        .arg("en0")
        .arg("down")
        .output();

    thread::sleep(Duration::from_millis(100));

    let _ = Command::new("/sbin/ifconfig").arg("en0").arg("up").output();

    Ok(())
}

/// Set the WiFi interface to a specific channel
#[cfg(target_os = "macos")]
pub fn set_channel(_interface: &str, channel: u8) -> Result<(), String> {
    use std::path::Path;

    // First disassociate from any network
    disassociate()?;

    // Try airport if available
    if Path::new(AIRPORT_PATH).exists() {
        let output = Command::new(AIRPORT_PATH)
            .arg(format!("-c{}", channel))
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                return Ok(());
            }
        }
    }

    // Note: tcpdump doesn't support channel switching directly
    // Would need to restart capture on new channel
    Err("Channel switching not available without airport utility".to_string())
}

/// Enable monitor mode (sniffing) on the specified interface and channel
/// Returns a handle to stop sniffing
#[cfg(target_os = "macos")]
pub struct SniffHandle {
    process: std::process::Child,
    #[allow(dead_code)]
    interface: String,
}

#[cfg(target_os = "macos")]
impl SniffHandle {
    /// Stop sniffing
    pub fn stop(mut self) -> Result<(), String> {
        self.process
            .kill()
            .map_err(|e| format!("Failed to stop sniffing: {}", e))?;
        Ok(())
    }
}

/// Start sniffing (monitor mode) on the specified interface and channel
/// Note: This will create pcap files in /tmp/
#[cfg(target_os = "macos")]
pub fn start_sniff(interface: &str, channel: u8) -> Result<SniffHandle, String> {
    // First disassociate from any network
    disassociate()?;

    let mut child = Command::new("sudo")
        .arg(AIRPORT_PATH)
        .arg(interface)
        .arg("sniff")
        .arg(channel.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start airport sniff: {}", e))?;

    // Give it a moment to start
    thread::sleep(Duration::from_millis(500));

    // Check if process is still running
    match child.try_wait() {
        Ok(Some(status)) => {
            return Err(format!(
                "Airport sniff exited immediately with status: {}",
                status
            ));
        }
        Ok(None) => {
            // Process is still running, good
        }
        Err(e) => {
            return Err(format!("Error checking sniff process: {}", e));
        }
    }

    Ok(SniffHandle {
        process: child,
        interface: interface.to_string(),
    })
}

/// Check if monitor mode is available for the interface
#[cfg(target_os = "macos")]
pub fn check_monitor_capability(_interface: &str) -> bool {
    use std::path::Path;

    // Check if we have any method available for monitor mode
    if Path::new(AIRPORT_PATH).exists() {
        // Try to get interface info
        let output = Command::new(AIRPORT_PATH).arg("-I").output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if !stdout.is_empty() && stdout.contains("SSID") {
                return true;
            }
        }
    }

    // Check if tcpdump is available as fallback
    Path::new(TCPDUMP_PATH).exists()
}

/// Get current channel of the interface
#[cfg(target_os = "macos")]
pub fn get_current_channel(_interface: &str) -> Result<u8, String> {
    use std::path::Path;

    // Try airport first
    if Path::new(AIRPORT_PATH).exists() {
        let output = Command::new(AIRPORT_PATH).arg("-I").output();

        if let Ok(output) = output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if line.trim().starts_with("channel:") {
                        let parts: Vec<&str> = line.split(':').collect();
                        if parts.len() >= 2 {
                            let channel_str = parts[1].trim().split(',').next().unwrap_or("");
                            if let Ok(channel) = channel_str.parse::<u8>() {
                                return Ok(channel);
                            }
                        }
                    }
                }
            }
        }
    }

    // Try wdutil as fallback
    if Path::new(WDUTIL_PATH).exists() {
        let output = Command::new(WDUTIL_PATH).arg("info").output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("Channel") {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() >= 2 {
                        let channel_str = parts[1].trim().split(' ').next().unwrap_or("");
                        if let Ok(channel) = channel_str.parse::<u8>() {
                            return Ok(channel);
                        }
                    }
                }
            }
        }
    }

    Err("Could not determine current channel".to_string())
}

/// Enable monitor mode using tcpdump (modern approach when airport is unavailable)
#[cfg(target_os = "macos")]
fn enable_monitor_mode_tcpdump(interface: &str) -> Result<(), String> {
    use std::path::Path;

    if !Path::new(TCPDUMP_PATH).exists() {
        return Err("tcpdump not found".to_string());
    }

    // Start tcpdump with monitor mode flag in background
    let child = Command::new(TCPDUMP_PATH)
        .arg("-I") // Monitor mode flag
        .arg("-i")
        .arg(interface)
        .arg("-w")
        .arg(format!("/tmp/capture_{}.pcap", interface))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to start tcpdump: {}", e))?;

    // Detach the process so it runs in background
    std::mem::forget(child);

    Ok(())
}

/// Simple monitor mode enable for interfaces that support it
#[cfg(target_os = "macos")]
pub fn enable_monitor_mode(interface: &str) -> Result<(), String> {
    use std::path::Path;

    // Disassociate first
    disassociate()?;

    // Try airport sniff if available
    if Path::new(AIRPORT_PATH).exists() {
        // Try to start sniffing on channel 1
        let result = start_sniff(interface, 1);
        if result.is_ok() {
            // Forget the handle so it keeps running
            std::mem::forget(result);
            return Ok(());
        }
    }

    // Fallback to tcpdump
    enable_monitor_mode_tcpdump(interface)
}

/// Disable monitor mode
#[cfg(target_os = "macos")]
pub fn disable_monitor_mode(interface: &str) -> Result<(), String> {
    // Kill any running airport sniff or tcpdump processes on this interface
    let _ = Command::new("pkill")
        .arg("-f")
        .arg("airport.*sniff")
        .output();

    let _ = Command::new("pkill")
        .arg("-f")
        .arg(format!("tcpdump.*{}", interface))
        .output();

    // Bring interface down and up to reset it
    let _ = Command::new("/sbin/ifconfig")
        .arg(interface)
        .arg("down")
        .output();

    thread::sleep(Duration::from_millis(500));

    let _ = Command::new("/sbin/ifconfig")
        .arg(interface)
        .arg("up")
        .output();

    Ok(())
}

#[cfg(test)]
#[cfg(target_os = "macos")]
mod tests {
    use super::*;

    #[test]
    fn test_airport_path_exists() {
        use std::path::Path;
        assert!(
            Path::new(AIRPORT_PATH).exists(),
            "Airport utility not found at expected path"
        );
    }

    #[test]
    fn test_check_monitor_capability() {
        // This test might fail on systems without WiFi
        // Just verify the function doesn't panic
        let _ = check_monitor_capability("en0");
    }
}
