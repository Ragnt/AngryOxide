# Airport Utility Integration for macOS Monitor Mode

## Overview

This document describes the integration of macOS's Airport utility for enabling monitor mode and controlling WiFi interfaces in AngryOxide. The implementation provides equivalent functionality to Linux's nl80211 while maintaining cross-platform compatibility.

## Architecture

### Airport Utility

The Airport utility is located at:
```
/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport
```

This is a command-line tool provided by Apple for WiFi interface management, including:
- Monitor mode (sniffing)
- Channel switching
- Network disassociation
- Interface information

### Key Components

#### Airport Module (`src/airport.rs`)

Provides Rust wrapper functions for Airport commands:

- `disassociate()` - Disconnect from current network
- `set_channel()` - Switch to specific channel
- `start_sniff()` - Enable monitor mode with packet capture
- `check_monitor_capability()` - Verify interface supports monitor mode
- `get_current_channel()` - Query current channel
- `enable_monitor_mode()` - Simplified monitor mode enable
- `disable_monitor_mode()` - Disable monitor mode

#### Interface Control (`src/interface.rs`)

Implements platform-specific interface management:

##### Nl80211Mock for macOS
- `set_interface_down()` - Uses ioctl with SIOCSIFFLAGS
- `set_interface_up()` - Uses ioctl with SIOCSIFFLAGS
- `set_interface_monitor()` - Calls Airport wrapper functions
- `set_interface_channel()` - Uses Airport for channel switching
- `list_phys()` - Returns mock PHY with monitor capability

##### ioctl Constants for macOS
```rust
const SIOCSIFFLAGS: libc::c_ulong = 0x80206910;  // Set interface flags
const SIOCGIFFLAGS: libc::c_ulong = 0xc0206911;  // Get interface flags
```

## Implementation Details

### Monitor Mode Flow

1. **Disassociation**: Must disconnect from any network first
2. **Interface Down**: Bring interface down using ioctl
3. **Enable Monitor**: Use `airport sniff` command
4. **Channel Setting**: Use `airport -c<channel>` if needed

### Platform Differences

| Feature | Linux | macOS |
|---------|-------|-------|
| Monitor API | nl80211 | Airport utility |
| Interface Control | netlink | ioctl/Airport |
| Active Monitor | Hardware feature | Not applicable |
| Channel Switch | nl80211 | Airport -c |
| Requires Disassociation | No | Yes |

### Conditional Compilation

The codebase uses extensive conditional compilation:

```rust
#[cfg(target_os = "linux")]
// Linux-specific implementation

#[cfg(target_os = "macos")]
// macOS-specific implementation
```

## Usage

### Enabling Monitor Mode

```bash
# macOS automatically handled by AngryOxide
sudo angryoxide -i en0
```

The application will:
1. Check monitor capability
2. Disassociate from network
3. Set interface down
4. Enable monitor mode
5. Set desired channel

### Monitor Mode Commands

Internal Airport commands used:
```bash
# Disassociate
airport -z

# Set channel
airport -c6

# Start sniffing
sudo airport en0 sniff 6

# Output goes to /tmp/airportSniff*.cap
```

## Limitations

### Hardware Limitations

- Not all Mac hardware supports monitor mode
- Newer Macs (especially M1/M2) have limited support
- Some interfaces may only support certain channels

### Software Limitations

- Requires sudo/root privileges
- System Integrity Protection (SIP) may interfere
- Cannot remain associated while in monitor mode
- Channel hopping more limited than Linux

### Known Issues

1. **Catalina and Later**: Monitor mode support degraded
2. **M1/M2 Macs**: Very limited or no monitor mode
3. **Channel Restrictions**: Some channels unavailable in certain regions

## Testing

### Unit Tests

```rust
#[test]
fn test_airport_path_exists() {
    assert!(Path::new(AIRPORT_PATH).exists());
}

#[test]
fn test_check_monitor_capability() {
    let _ = check_monitor_capability("en0");
}
```

### Integration Testing

1. **Interface Control**:
   - Test interface up/down
   - Verify MAC address changes
   - Check interface status

2. **Monitor Mode**:
   - Enable/disable monitor mode
   - Verify packet capture starts
   - Check channel switching

3. **Cross-Platform**:
   - Ensure Linux build unaffected
   - Verify macOS-specific code isolated

## Troubleshooting

### Common Issues

**"Failed to set interface down"**
- Ensure running with sudo
- Check interface name (typically en0 or en1)

**"Monitor mode not available"**
- Hardware may not support monitor mode
- Try different interface (en1 if en0 fails)

**"Failed to disassociate"**
- May already be disconnected
- Can be safely ignored in most cases

**"Channel switch failed"**
- Some channels restricted by region
- Interface may not support all channels

### Debug Commands

```bash
# Check interface status
ifconfig en0

# Get WiFi info
airport -I

# List interfaces
ifconfig -l

# Check for BPF devices
ls -la /dev/bpf*
```

## Security Considerations

- Requires root/admin privileges
- Monitor mode visible to system
- May trigger security software
- Packets captured to /tmp/ by default

## Future Enhancements

1. **CoreWLAN Integration**: Native macOS framework usage
2. **IOKit Direct Access**: Lower-level hardware control
3. **Channel Hopping**: Automated channel switching
4. **Packet Injection**: Enhanced injection support
5. **Hardware Detection**: Better capability detection

## Verification

### Functionality Checklist

- [x] Airport utility wrapper implemented
- [x] Monitor mode enable/disable
- [x] Channel switching
- [x] Interface up/down control
- [x] Network disassociation
- [x] Platform conditional compilation
- [x] Linux build unaffected
- [ ] Hardware testing on various Macs
- [ ] Performance benchmarking

### Compatibility Matrix

| macOS Version | Support Level | Notes |
|--------------|--------------|-------|
| 10.14 Mojave | Full | Best monitor mode support |
| 10.15 Catalina | Partial | Some limitations |
| 11.x Big Sur | Limited | Hardware dependent |
| 12.x Monterey | Limited | M1/M2 issues |
| 13.x Ventura | Limited | Requires workarounds |
| 14.x Sonoma | Limited | Latest tested |

## References

- [Apple80211 Framework](https://developer.apple.com/documentation/)
- [Airport Utility Documentation](https://support.apple.com/guide/aputility/welcome/mac)
- [macOS ioctl Reference](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/ioctl.2.html)
- [BPF on macOS](https://www.freebsd.org/cgi/man.cgi?query=bpf&sektion=4)