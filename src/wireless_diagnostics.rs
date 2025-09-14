// Modern macOS WiFi monitor mode implementation
// Uses tcpdump and Wireless Diagnostics as airport is deprecated

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const AIRPORT_PATH: &str =
    "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport";
const TCPDUMP_PATH: &str = "/usr/sbin/tcpdump";
const WIRELESS_DIAGNOSTICS_PATH: &str = "/System/Library/CoreServices/Applications/Wireless Diagnostics.app/Contents/MacOS/Wireless Diagnostics";

pub struct MonitorMode {
    interface: String,
    process: Option<Child>,
    running: Arc<AtomicBool>,
}

impl MonitorMode {
    pub fn new(interface: &str) -> Self {
        MonitorMode {
            interface: interface.to_string(),
            process: None,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Check which monitor mode method is available
    pub fn detect_available_method() -> MonitorMethod {
        // Check for airport first (older but still works on some systems)
        if Path::new(AIRPORT_PATH).exists() {
            // Try to run airport to see if it actually works
            let result = Command::new(AIRPORT_PATH).arg("-I").output();

            if result.is_ok() {
                return MonitorMethod::Airport;
            }
        }

        // Check for tcpdump (should always be available)
        if Path::new(TCPDUMP_PATH).exists() {
            return MonitorMethod::Tcpdump;
        }

        // Fallback to Wireless Diagnostics if available
        if Path::new(WIRELESS_DIAGNOSTICS_PATH).exists() {
            return MonitorMethod::WirelessDiagnostics;
        }

        MonitorMethod::None
    }

    /// Enable monitor mode using the best available method
    pub fn enable(&mut self) -> Result<(), String> {
        let method = Self::detect_available_method();

        match method {
            MonitorMethod::Airport => self.enable_with_airport(),
            MonitorMethod::Tcpdump => self.enable_with_tcpdump(),
            MonitorMethod::WirelessDiagnostics => self.enable_with_wireless_diagnostics(),
            MonitorMethod::None => Err("No monitor mode method available".to_string()),
        }
    }

    /// Enable monitor mode using legacy airport utility
    fn enable_with_airport(&mut self) -> Result<(), String> {
        // First disassociate
        Command::new(AIRPORT_PATH)
            .arg("-z")
            .output()
            .map_err(|e| format!("Failed to disassociate: {}", e))?;

        // Start sniffing
        let child = Command::new(AIRPORT_PATH)
            .arg(&self.interface)
            .arg("sniff")
            .arg("1") // Channel 1 as default
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to start airport sniff: {}", e))?;

        self.process = Some(child);
        self.running.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Enable monitor mode using tcpdump (modern approach)
    fn enable_with_tcpdump(&mut self) -> Result<(), String> {
        // Disassociate from network first
        self.disassociate()?;

        // Use tcpdump with monitor mode flag
        let child = Command::new(TCPDUMP_PATH)
            .arg("-I") // Monitor mode flag
            .arg("-i")
            .arg(&self.interface)
            .arg("-w")
            .arg("-") // Write to stdout
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to start tcpdump: {}", e))?;

        self.process = Some(child);
        self.running.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Enable monitor mode using Wireless Diagnostics sniffer
    fn enable_with_wireless_diagnostics(&mut self) -> Result<(), String> {
        // This is more complex as Wireless Diagnostics is a GUI app
        // We can try to use it via command line but it's limited

        // First disassociate
        self.disassociate()?;

        // Try to use the sniffer command if available
        let result = Command::new("/usr/bin/open")
            .arg("-a")
            .arg("Wireless Diagnostics")
            .arg("--args")
            .arg("--sniffer")
            .arg(&self.interface)
            .output();

        match result {
            Ok(_) => {
                self.running.store(true, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => Err(format!("Failed to start Wireless Diagnostics: {}", e)),
        }
    }

    /// Disable monitor mode
    pub fn disable(&mut self) -> Result<(), String> {
        self.running.store(false, Ordering::Relaxed);

        if let Some(mut child) = self.process.take() {
            // Try to terminate gracefully
            child
                .kill()
                .map_err(|e| format!("Failed to stop monitor mode: {}", e))?;
            child
                .wait()
                .map_err(|e| format!("Failed to wait for process: {}", e))?;
        }

        // Re-enable normal mode on interface
        self.enable_managed_mode()?;

        Ok(())
    }

    /// Disassociate from current network
    fn disassociate(&self) -> Result<(), String> {
        // Try airport first
        if Path::new(AIRPORT_PATH).exists() {
            let result = Command::new(AIRPORT_PATH).arg("-z").output();

            if result.is_ok() {
                return Ok(());
            }
        }

        // Try using ifconfig to bring interface down/up
        Command::new("/sbin/ifconfig")
            .arg(&self.interface)
            .arg("down")
            .output()
            .map_err(|e| format!("Failed to bring interface down: {}", e))?;

        thread::sleep(Duration::from_millis(100));

        Command::new("/sbin/ifconfig")
            .arg(&self.interface)
            .arg("up")
            .output()
            .map_err(|e| format!("Failed to bring interface up: {}", e))?;

        Ok(())
    }

    /// Re-enable managed mode on interface
    fn enable_managed_mode(&self) -> Result<(), String> {
        // Bring interface down and up to reset it
        Command::new("/sbin/ifconfig")
            .arg(&self.interface)
            .arg("down")
            .output()
            .map_err(|e| format!("Failed to bring interface down: {}", e))?;

        thread::sleep(Duration::from_millis(500));

        Command::new("/sbin/ifconfig")
            .arg(&self.interface)
            .arg("up")
            .output()
            .map_err(|e| format!("Failed to bring interface up: {}", e))?;

        Ok(())
    }

    /// Set WiFi channel (if supported by current method)
    pub fn set_channel(&self, channel: u8) -> Result<(), String> {
        let method = Self::detect_available_method();

        match method {
            MonitorMethod::Airport => {
                // Use airport to set channel
                Command::new(AIRPORT_PATH)
                    .arg("-c")
                    .arg(channel.to_string())
                    .output()
                    .map_err(|e| format!("Failed to set channel: {}", e))?;
                Ok(())
            }
            _ => {
                // For tcpdump and others, channel switching is limited
                // Would need to restart capture on new channel
                Err("Channel switching not supported with current method".to_string())
            }
        }
    }

    /// Check if monitor mode is supported
    pub fn is_supported(&self) -> bool {
        Self::detect_available_method() != MonitorMethod::None
    }
}

#[derive(Debug, PartialEq)]
pub enum MonitorMethod {
    Airport,
    Tcpdump,
    WirelessDiagnostics,
    None,
}

/// Get current WiFi channel
pub fn get_current_channel(_interface: &str) -> Result<u8, String> {
    // Try airport first
    if Path::new(AIRPORT_PATH).exists() {
        let output = Command::new(AIRPORT_PATH)
            .arg("-I")
            .output()
            .map_err(|e| format!("Failed to get interface info: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("channel:") {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 {
                    let channel_str = parts[1].trim().split(',').next().unwrap_or("0");
                    return channel_str
                        .parse::<u8>()
                        .map_err(|_| "Failed to parse channel".to_string());
                }
            }
        }
    }

    // Try using wdutil info as fallback
    let output = Command::new("wdutil")
        .arg("info")
        .output()
        .map_err(|e| format!("Failed to run wdutil: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.contains("Channel") {
            // Parse channel from wdutil output
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 2 {
                let channel_str = parts[1].trim().split(' ').next().unwrap_or("0");
                return channel_str
                    .parse::<u8>()
                    .map_err(|_| "Failed to parse channel".to_string());
            }
        }
    }

    Err("Could not determine current channel".to_string())
}

/// Get WiFi interface information using wdutil
pub fn get_interface_info_wdutil() -> Result<String, String> {
    let output = Command::new("wdutil")
        .arg("info")
        .output()
        .map_err(|e| format!("Failed to run wdutil: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_monitor_method() {
        let method = MonitorMode::detect_available_method();
        println!("Detected monitor method: {:?}", method);
        assert_ne!(method, MonitorMethod::None);
    }

    #[test]
    fn test_get_interface_info() {
        if let Ok(info) = get_interface_info_wdutil() {
            println!("Interface info:\n{}", info);
            assert!(!info.is_empty());
        }
    }
}
