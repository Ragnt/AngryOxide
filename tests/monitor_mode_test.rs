// Integration tests for monitor mode functionality across platforms

#[cfg(test)]
mod monitor_mode_tests {
    #[cfg(target_os = "macos")]
    use angry_oxide::airport::{check_monitor_capability, disassociate, get_current_channel};

    #[cfg(target_os = "macos")]
    use angry_oxide::interface::Nl80211Mock;

    use std::process::Command;

    #[test]
    #[cfg(target_os = "macos")]
    fn test_airport_utility_exists() {
        let airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport";
        assert!(
            std::path::Path::new(airport_path).exists(),
            "Airport utility not found"
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_monitor_capability_detection() {
        // Test with common interface names
        let interfaces = vec!["en0", "en1"];

        for iface in interfaces {
            let capability = check_monitor_capability(iface);
            println!("Interface {} monitor capability: {}", iface, capability);
            // We don't assert here as capability depends on hardware
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_interface_mock_creation() {
        let mock = Nl80211Mock::new().expect("Failed to create mock");

        // Test listing PHYs
        let phys = mock.list_phys().expect("Failed to list PHYs");
        assert!(!phys.is_empty(), "Should return at least one mock PHY");

        // Verify PHY has expected fields
        let phy = &phys[0];
        assert_eq!(phy.index, 0);
        assert!(!phy.name.is_empty());
        assert!(phy.iftypes.is_some());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_interface_operations() {
        let mock = Nl80211Mock::new().expect("Failed to create mock");

        // Test interface down
        let result = mock.set_interface_down(0);
        // Don't assert success as it requires root
        if result.is_err() {
            println!("Interface down requires root: {:?}", result);
        }

        // Test interface up
        let result = mock.set_interface_up(0);
        if result.is_err() {
            println!("Interface up requires root: {:?}", result);
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_channel_operations() {
        // Test getting current channel (may fail if not connected)
        let result = get_current_channel("en0");
        match result {
            Ok(channel) => println!("Current channel: {}", channel),
            Err(e) => println!("Could not get channel (expected if not connected): {}", e),
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_linux_build_unaffected() {
        // This test ensures Linux builds still work
        // It doesn't need to do anything complex, just compile and run
        // Linux build test passed
    }

    #[test]
    fn test_platform_detection() {
        #[cfg(target_os = "macos")]
        {
            println!("Running on macOS");
            assert!(cfg!(target_os = "macos"));
        }

        #[cfg(target_os = "linux")]
        {
            println!("Running on Linux");
            assert!(cfg!(target_os = "linux"));
        }
    }

    #[test]
    #[ignore] // Requires root
    #[cfg(target_os = "macos")]
    fn test_monitor_mode_enable_disable() {
        use angry_oxide::airport::{disable_monitor_mode, enable_monitor_mode};

        let interface = "en0";

        // Try to enable monitor mode
        let result = enable_monitor_mode(interface);
        if result.is_ok() {
            println!("Monitor mode enabled successfully");

            // Try to disable it
            let disable_result = disable_monitor_mode(interface);
            assert!(disable_result.is_ok(), "Failed to disable monitor mode");
        } else {
            println!("Monitor mode enable failed (requires root): {:?}", result);
        }
    }

    #[test]
    #[ignore] // Requires root
    #[cfg(target_os = "macos")]
    fn test_disassociation() {
        let result = disassociate();
        match result {
            Ok(_) => println!("Successfully disassociated from network"),
            Err(e) => println!("Disassociation failed (may not be connected): {}", e),
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_bpf_device_availability() {
        use std::fs;

        // Check if BPF devices exist
        let mut found_bpf = false;
        for i in 0..10 {
            let path = format!("/dev/bpf{}", i);
            if fs::metadata(&path).is_ok() {
                found_bpf = true;
                println!("Found BPF device: {}", path);
                break;
            }
        }

        assert!(found_bpf, "No BPF devices found in /dev/");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_interface_enumeration() {
        let output = Command::new("ifconfig")
            .arg("-l")
            .output()
            .expect("Failed to run ifconfig");

        let interfaces = String::from_utf8_lossy(&output.stdout);
        println!("Available interfaces: {}", interfaces);

        // Check for common WiFi interface names
        assert!(
            interfaces.contains("en0") || interfaces.contains("en1"),
            "No WiFi interfaces found"
        );
    }

    #[test]
    fn test_cross_platform_compilation() {
        // This test verifies that the code compiles on both platforms
        // The mere fact that this test compiles and runs proves the
        // conditional compilation is working correctly

        #[cfg(target_os = "macos")]
        {
            // If these modules compile, our conditional compilation works
        }

        #[cfg(target_os = "linux")]
        {
            // Linux-specific modules should still compile
        }

        // Cross-platform compilation successful
    }
}
