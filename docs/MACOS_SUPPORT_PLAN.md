# macOS Support Implementation Plan for AngryOxide

## Executive Summary

This document outlines a comprehensive plan to add macOS compatibility to AngryOxide while maintaining full Linux support. The implementation uses conditional compilation and platform abstraction layers to keep the codebase unified.

## Current State Analysis

### Existing Infrastructure
- Basic conditional compilation structure already in place
- Platform abstraction files created:
  - `src/interface.rs` - Wireless interface management abstraction
  - `src/rawsocks.rs` - Raw socket abstraction (stubs for macOS)
- UI clipboard handling already supports both platforms

### Platform-Specific Components Requiring Implementation

1. **Raw Socket Operations** (`src/rawsocks.rs`)
   - Linux: Uses AF_PACKET sockets
   - macOS: Needs BPF (Berkeley Packet Filter) implementation

2. **Wireless Interface Management** (`src/interface.rs`)
   - Linux: Uses nl80211 via netlink
   - macOS: Needs CoreWLAN/IOKit implementation

3. **Monitor Mode Support**
   - Linux: Native support via nl80211
   - macOS: Limited; requires specific hardware and drivers

4. **Packet Injection**
   - Linux: Direct write to AF_PACKET socket
   - macOS: BPF device with DLT_IEEE802_11_RADIO

## Implementation Strategy

### Phase 1: Core Infrastructure (Week 1-2) ✅ COMPLETED

#### 1.1 BPF Raw Socket Implementation ✅
```rust
// src/rawsocks.rs - macOS implementation
- ✅ Implement BPF device discovery (/dev/bpf*)
- ✅ Set up proper BPF filters for 802.11 frames
- ✅ Configure immediate mode and buffer sizes
- ✅ Handle radiotap headers for injection
```

#### 1.2 Update Build Configuration ✅
```toml
# Cargo.toml
[target.'cfg(target_os = "macos")'.dependencies]
core-foundation = "0.9" ✅
core-foundation-sys = "0.8" ✅
system-configuration = "0.5" ✅
# iokit-sys = "0.1" - Not added yet, may be needed later
```

### Phase 2: Wireless Interface Management (Week 2-3) ✅ COMPLETED

**Status**: Interface management fully implemented using Airport utility and ioctl

#### 2.1 Airport Utility Integration ✅
```rust
// src/airport.rs - COMPLETED
- ✅ Enumerate wireless interfaces using Airport
- ✅ Get interface capabilities and state
- ✅ Handle channel switching via Airport
- ✅ Implement monitor mode detection and control
```

#### 2.2 Interface Abstraction Updates ✅
```rust
// src/interface.rs - COMPLETED
- ✅ Complete Nl80211Mock implementation with Airport integration
- ✅ Implement interface up/down control via ioctl (SIOCSIFFLAGS)
- ✅ MAC address management
- ✅ Channel and frequency management
```

### Phase 3: Monitor Mode & Packet Injection (Week 3-4) ✅ COMPLETED

**Status**: Full monitor mode support and packet injection implemented

#### 3.1 Airport Utility Integration ✅
```rust
// src/airport.rs - COMPLETED
- ✅ Detect airport utility availability
- ✅ Implement monitor mode enable/disable
- ✅ Handle dissociation requirements
- ✅ Manage channel hopping limitations
- ✅ SniffHandle for managing monitor mode process
```

#### 3.2 BPF Packet Injection ✅ COMPLETED
```rust
// Update src/rawsocks.rs
- ✅ Implement proper radiotap header construction
- ✅ Handle BPF write semantics
- ✅ Add retry logic for injection failures
- ✅ BPF header parsing and packet extraction
- ✅ Multiple packet handling per read()
- ✅ Alignment handling (BPF_WORDALIGN)
```

### Phase 4: Platform Compatibility Layer (Week 4-5)

#### 4.1 Common Interface Traits
```rust
// src/platform.rs - New file
trait WirelessInterface {
    fn set_monitor_mode(&self, enable: bool) -> Result<()>;
    fn set_channel(&self, channel: u8, band: Band) -> Result<()>;
    fn inject_frame(&self, frame: &[u8]) -> Result<()>;
    fn receive_frame(&self) -> Result<Vec<u8>>;
}
```

#### 4.2 Factory Pattern for Platform Selection
```rust
// src/platform.rs
pub fn create_wireless_interface(name: &str) -> Box<dyn WirelessInterface> {
    #[cfg(target_os = "linux")]
    return Box::new(LinuxInterface::new(name));

    #[cfg(target_os = "macos")]
    return Box::new(MacOSInterface::new(name));
}
```

### Phase 5: Testing & Validation (Week 5-6)

#### 5.1 Unit Tests
- Platform-specific test modules
- Mock BPF devices for testing
- Interface enumeration tests

#### 5.2 Integration Tests
- Cross-platform frame injection tests
- Monitor mode capability detection
- Channel switching validation

## Technical Challenges & Solutions

### Challenge 1: Limited Monitor Mode Support
**Problem**: macOS restricts monitor mode and not all hardware supports it.
**Solution**:
- Runtime capability detection
- Graceful degradation with informative errors
- Document supported hardware list

### Challenge 2: BPF Complexity
**Problem**: BPF has different semantics than AF_PACKET.
**Solution**:
- Abstract packet I/O behind traits
- Implement comprehensive error handling
- Add BPF-specific optimizations

### Challenge 3: Channel Control Limitations
**Problem**: macOS doesn't allow channel changes while associated.
**Solution**:
- Force disassociation before channel change
- Cache and restore network state
- Implement channel validation

### Challenge 4: Root/Admin Requirements
**Problem**: Both platforms need elevated privileges differently.
**Solution**:
- Platform-specific privilege checking
- Clear error messages for permission issues
- Document setup requirements

## Build and Distribution

### Development Build
```bash
# macOS
cargo build --release

# Linux
cargo build --release

# Cross-platform testing
cargo test --all-features
```

### CI/CD Updates
```yaml
# .github/workflows/ci.yml
matrix:
  os: [ubuntu-latest, macos-latest]
  rust: [stable, nightly]
```

### Platform-Specific Features
```toml
[features]
default = ["bundled"]
macos = ["bpf", "corewlan"]
linux = ["nl80211", "af-packet"]
```

## Performance Considerations

### macOS Optimizations
- BPF buffer sizing for reduced latency
- Batch packet processing where possible
- Minimize CoreWLAN API calls

### Cross-Platform Performance
- Conditional compilation for hot paths
- Platform-specific SIMD optimizations
- Zero-copy packet handling where possible

## Security Considerations

### macOS-Specific Security
- Respect System Integrity Protection (SIP)
- Handle macOS privacy permissions
- Secure keychain integration for stored networks

### Code Signing
- Document code signing requirements
- Provide unsigned build option
- Include notarization instructions

## Documentation Updates

### README.md Additions
- macOS installation instructions
- Supported hardware list
- Known limitations

### CLAUDE.md Updates
- Platform-specific build commands
- Testing procedures
- Troubleshooting guide

### Platform-Specific Docs
- `docs/MACOS.md` - Detailed macOS setup
- `docs/LINUX.md` - Linux-specific features
- `docs/PLATFORM_SUPPORT.md` - Compatibility matrix

## Migration Path for Existing Users

1. **Backward Compatibility**: All existing Linux functionality preserved
2. **Feature Parity**: Document any features not available on macOS
3. **Configuration**: Platform-specific config file sections

## Success Metrics

- [✅] Successful compilation on macOS without warnings
- [✅] Basic packet capture working on macOS (BPF implementation)
- [✅] Monitor mode detection and control (Airport utility)
- [✅] All existing Linux tests passing (Linux build unaffected)
- [✅] Platform-specific implementation for macOS
- [✅] Documentation complete (BPF_IMPLEMENTATION.md, AIRPORT_INTEGRATION.md)
- [ ] Hardware testing on actual Mac devices
- [ ] CI/CD pipeline includes macOS

## Timeline & Progress

- **Week 1-2**: Core infrastructure and BPF implementation ✅ COMPLETED
  - BPF device opening and configuration implemented
  - Basic ioctl operations for BPF set up
  - Conditional compilation structure established

- **Week 2-3**: Interface management and CoreWLAN ⚠️ IN PROGRESS
  - Basic interface abstraction created
  - Placeholder implementations for most operations
  - Need full CoreWLAN integration

- **Week 3-4**: Monitor mode and injection 🔄 PENDING
- **Week 4-5**: Compatibility layer and integration 🔄 PENDING
- **Week 5-6**: Testing, documentation, and polish 🔄 PENDING

## Current Status (as of implementation)

### ✅ Completed
- BPF raw socket implementation for macOS
  - BPF device opening and configuration
  - Packet reading with BPF header parsing
  - Packet writing/injection support
  - Buffer alignment handling
  - Unit tests for BPF functionality
- Airport utility integration for macOS
  - Monitor mode enable/disable
  - Channel switching
  - Network disassociation
  - Interface capability detection
- Complete interface abstraction layer
  - Nl80211Mock with full Airport integration
  - Interface up/down control via ioctl
  - MAC address management
  - Frequency and channel management
- Platform-specific build configuration
- Conditional compilation throughout codebase
- UI clipboard handling for macOS
- Band/WiFiBand type compatibility
- Platform-specific packet I/O in main.rs
- Comprehensive documentation
  - BPF_IMPLEMENTATION.md
  - AIRPORT_INTEGRATION.md

### 🔄 Pending
- Hardware testing on actual Mac devices
- Full integration testing suite
- CI/CD updates for macOS
- Performance optimization
- CoreWLAN integration (future enhancement)

## Risk Mitigation

1. **Hardware Limitations**: Document clearly, provide capability detection
2. **API Changes**: Abstract behind interfaces, version detection
3. **Performance**: Profile and optimize critical paths
4. **Maintenance**: Comprehensive testing, clear separation of concerns

## Future Enhancements

### Phase 2 Possibilities
- Native macOS UI using SwiftUI
- Integration with macOS Network Extension framework
- Keychain integration for credential storage
- macOS-specific packet capture optimizations

### Long-term Goals
- Windows support using WinPcap/Npcap
- BSD family support
- Mobile platform considerations