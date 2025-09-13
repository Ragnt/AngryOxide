# Modern macOS Monitor Mode Implementation

## Overview

This document describes the updated monitor mode implementation for macOS that addresses the deprecation of the Airport utility in favor of modern alternatives like tcpdump and wdutil.

## Background

Apple has been deprecating the Airport utility since macOS Sonoma (14.0). While Airport still exists on many systems, it may not be available or functional on newer macOS versions. This implementation provides a robust fallback strategy to ensure monitor mode works across all macOS versions.

## Implementation Strategy

### 1. Multi-Method Approach

The implementation now supports three methods for monitor mode, with automatic fallback:

1. **Airport (Legacy)** - Still works on many systems
2. **tcpdump (Modern)** - Available on all macOS versions
3. **wdutil (Information)** - For WiFi interface information

### 2. Method Detection

The system automatically detects which methods are available:

```rust
pub fn detect_available_method() -> MonitorMethod {
    // Check for airport first (older but still works on some systems)
    if Path::new(AIRPORT_PATH).exists() {
        // Try to run airport to see if it actually works
        let result = Command::new(AIRPORT_PATH)
            .arg("-I")
            .output();

        if result.is_ok() {
            return MonitorMethod::Airport;
        }
    }

    // Check for tcpdump (should always be available)
    if Path::new(TCPDUMP_PATH).exists() {
        return MonitorMethod::Tcpdump;
    }

    MonitorMethod::None
}
```

## Key Components

### 1. wireless_diagnostics.rs

A new module that provides:
- Unified monitor mode interface
- Automatic method selection
- tcpdump-based packet capture
- wdutil integration for info

### 2. Updated airport.rs

Enhanced with fallback support:
- Tries Airport first if available
- Falls back to tcpdump for monitor mode
- Uses wdutil for channel information
- Graceful degradation

### 3. Monitor Mode Methods

#### Airport Method (Legacy)
```bash
# Disassociate
airport -z

# Start monitor mode
sudo airport en0 sniff 6

# Set channel
airport -c6
```

#### tcpdump Method (Modern)
```bash
# Start monitor mode with tcpdump
sudo tcpdump -I -i en0 -w capture.pcap

# -I flag enables monitor mode
# Captures at 802.11 layer
```

#### wdutil Method (Information)
```bash
# Get WiFi information
wdutil info

# Note: wdutil doesn't support monitor mode directly
# Used for interface information only
```

## Usage

### Enable Monitor Mode

The system automatically selects the best available method:

```rust
let mut monitor = MonitorMode::new("en0");
monitor.enable()?;  // Automatically uses best available method
```

### Channel Switching

```rust
// Works with Airport, limited with tcpdump
monitor.set_channel(6)?;
```

### Disable Monitor Mode

```rust
monitor.disable()?;  // Cleans up regardless of method used
```

## Compatibility Matrix

| macOS Version | Airport | tcpdump | wdutil | Monitor Mode |
|--------------|---------|---------|--------|--------------|
| 10.14 Mojave | ✅ | ✅ | ❌ | Full |
| 10.15 Catalina | ✅ | ✅ | ✅ | Full |
| 11.x Big Sur | ⚠️ | ✅ | ✅ | Limited |
| 12.x Monterey | ⚠️ | ✅ | ✅ | Limited |
| 13.x Ventura | ⚠️ | ✅ | ✅ | Limited |
| 14.x Sonoma | ❌ | ✅ | ✅ | tcpdump only |
| 15.x Sequoia | ❌ | ✅ | ✅ | tcpdump only |

⚠️ = May work depending on hardware/configuration
❌ = Not available or non-functional

## Limitations

### tcpdump Method
1. **Channel Switching**: Requires restarting capture
2. **Performance**: May have higher overhead than Airport
3. **Permissions**: Requires sudo/root
4. **Output**: Creates pcap files that need processing

### Hardware Limitations
1. **M1/M2 Macs**: Very limited monitor mode support
2. **USB Adapters**: May be required for full functionality
3. **Driver Support**: Varies by hardware model

### System Limitations
1. **SIP**: System Integrity Protection may interfere
2. **Permissions**: Requires elevated privileges
3. **Network Stack**: Cannot be associated while monitoring

## Testing

### Check Available Methods
```bash
# Run the detection test
cargo test test_detect_monitor_method

# Manual check
ls -la /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport
which tcpdump
which wdutil
```

### Test Monitor Mode
```bash
# With Airport (if available)
sudo airport en0 sniff 6

# With tcpdump
sudo tcpdump -I -i en0

# Check if packets are captured
tcpdump -r /tmp/capture_en0.pcap | head
```

## Troubleshooting

### "Airport not found"
- Expected on macOS Sonoma and later
- System will automatically use tcpdump

### "tcpdump: en0: You don't have permission"
- Requires sudo/root privileges
- Run with: `sudo cargo run`

### "No monitor mode method available"
- Extremely rare, tcpdump should always be present
- Check: `which tcpdump`
- Reinstall Xcode Command Line Tools if needed

### "Channel switching not supported"
- Normal with tcpdump method
- Must restart capture for new channel

## Future Enhancements

1. **libpcap Integration**: Direct library usage instead of tcpdump command
2. **CoreWLAN Framework**: Native macOS framework integration
3. **Packet Filtering**: BPF filters for efficiency
4. **Real-time Processing**: Stream processing instead of file-based
5. **Hardware Detection**: Automatic capability detection

## Migration Guide

### For Users

No changes required. The system automatically selects the best available method.

### For Developers

1. Use the new `MonitorMode` struct from `wireless_diagnostics.rs`
2. Don't assume Airport is available
3. Handle channel switching limitations gracefully
4. Test on multiple macOS versions

## Conclusion

This implementation ensures AngryOxide continues to work on modern macOS versions despite Apple's deprecation of the Airport utility. The fallback strategy provides robust monitor mode support across all macOS versions while maintaining backward compatibility.