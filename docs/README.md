# AngryOxide Documentation

This directory contains all technical documentation for the AngryOxide macOS implementation.

## macOS Support Documentation

### Implementation Guides

- [**MACOS_SUPPORT_PLAN.md**](MACOS_SUPPORT_PLAN.md) - Original comprehensive plan for adding macOS support
- [**IMPLEMENTATION_SUMMARY.md**](IMPLEMENTATION_SUMMARY.md) - Summary of Phase 1 implementation
- [**IMPLEMENTATION_COMPLETE.md**](IMPLEMENTATION_COMPLETE.md) - Final implementation status with all features
- [**MACOS_PARITY_COMPLETE.md**](MACOS_PARITY_COMPLETE.md) - Full feature parity achievement documentation

### Technical Documentation

- [**BPF_IMPLEMENTATION.md**](BPF_IMPLEMENTATION.md) - Berkeley Packet Filter implementation for packet capture/injection
- [**AIRPORT_INTEGRATION.md**](AIRPORT_INTEGRATION.md) - Airport utility integration for monitor mode
- [**MODERN_MACOS_MONITOR_MODE.md**](MODERN_MACOS_MONITOR_MODE.md) - Modern monitor mode using tcpdump/wdutil

## Quick Reference

### Key Features Implemented

1. **Packet Capture/Injection** - Full BPF implementation
2. **Monitor Mode** - Airport utility with tcpdump fallback
3. **Interface Management** - Complete ioctl-based control
4. **MAC Operations** - Address spoofing for attacks
5. **Hardware Detection** - Chipset and capability enumeration

### Platform Compatibility

| Feature | Linux | macOS |
|---------|-------|-------|
| Monitor Mode | ✅ nl80211 | ✅ Airport/tcpdump |
| Packet Injection | ✅ AF_PACKET | ✅ BPF |
| MAC Spoofing | ✅ Native | ✅ ioctl |
| Channel Control | ✅ Native | ✅ Airport/tcpdump |
| Power Management | ✅ Native | ✅ pmset |

### File Structure

```
docs/
├── README.md                       # This file
├── MACOS_SUPPORT_PLAN.md          # Original planning document
├── IMPLEMENTATION_SUMMARY.md       # Phase 1 summary
├── IMPLEMENTATION_COMPLETE.md      # Final implementation
├── MACOS_PARITY_COMPLETE.md       # Feature parity documentation
├── BPF_IMPLEMENTATION.md          # BPF technical details
├── AIRPORT_INTEGRATION.md         # Airport utility usage
└── MODERN_MACOS_MONITOR_MODE.md   # Modern monitor mode approach
```

## For Developers

When working on macOS-specific features:

1. Review [MACOS_SUPPORT_PLAN.md](MACOS_SUPPORT_PLAN.md) for architecture
2. Check [BPF_IMPLEMENTATION.md](BPF_IMPLEMENTATION.md) for packet handling
3. See [AIRPORT_INTEGRATION.md](AIRPORT_INTEGRATION.md) for WiFi control
4. Reference [MACOS_PARITY_COMPLETE.md](MACOS_PARITY_COMPLETE.md) for feature status

## Related Files

- `../README.md` - Main project README
- `src/macos_interface.rs` - Interface management implementation
- `src/macos_monitor.rs` - Monitor mode detection
- `src/airport.rs` - Airport utility wrapper
- `src/wireless_diagnostics.rs` - Modern monitor mode wrapper
- `src/rawsocks.rs` - BPF raw socket implementation