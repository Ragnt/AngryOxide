# BPF Packet Capture/Injection Implementation for macOS

## Overview

This document describes the Berkeley Packet Filter (BPF) implementation for packet capture and injection in AngryOxide on macOS. The implementation provides equivalent functionality to Linux's AF_PACKET sockets while maintaining cross-platform compatibility.

## Architecture

### BPF Device Interface

On macOS, raw packet access is provided through BPF devices (`/dev/bpf*`). The implementation:

1. **Device Discovery**: Iterates through `/dev/bpf0` to `/dev/bpf255` to find an available device
2. **Interface Binding**: Binds the BPF device to a specific network interface
3. **Configuration**: Sets up immediate mode, promiscuous mode, and data link type
4. **Packet I/O**: Handles reading packets with BPF headers and writing raw packets

### Key Components

#### BPF Header Structure (`src/rawsocks.rs`)

```rust
#[repr(C)]
pub struct bpf_hdr {
    pub bh_tstamp: timeval,     // timestamp
    pub bh_caplen: u32,         // length of captured portion
    pub bh_datalen: u32,        // original length of packet
    pub bh_hdrlen: u16,         // length of bpf header + padding
}
```

#### Alignment Handling

BPF requires packets to be aligned on word boundaries:
- `BPF_ALIGNMENT`: 4 bytes (32-bit alignment)
- `bpf_wordalign()`: Rounds up to nearest word boundary

#### Packet Reading Flow

1. Read from BPF device (may return multiple packets)
2. Parse BPF header from buffer
3. Extract packet data (skip BPF header)
4. Handle alignment for next packet
5. Return first packet (could be extended to handle multiple)

#### Packet Writing Flow

1. Prepare packet with radiotap header (if needed)
2. Write directly to BPF device
3. BPF handles injection at data link layer

## Platform Abstraction

### Conditional Compilation

The codebase uses `#[cfg(target_os = "...")]` attributes to separate platform-specific code:

- **Linux**: Uses `libc::read/write` with AF_PACKET sockets
- **macOS**: Uses BPF-specific `read_bpf_packet/write_bpf_packet` functions

### Main Entry Points

#### `read_frame()` in `src/main.rs`
```rust
#[cfg(target_os = "linux")]
// Direct read from socket

#[cfg(target_os = "macos")]
// BPF packet extraction
```

#### `write_packet()` in `src/main.rs`
```rust
#[cfg(target_os = "linux")]
// Direct write to socket

#[cfg(target_os = "macos")]
// BPF packet injection
```

## Configuration Details

### BPF ioctl Constants

```rust
const BIOCGBLEN: c_uint = 0x40044266;      // Get buffer length
const BIOCSBLEN: c_uint = 0xc0044266;      // Set buffer length
const BIOCSETIF: c_uint = 0x8020426c;      // Bind to interface
const BIOCIMMEDIATE: c_uint = 0x80044270;  // Immediate mode
const BIOCSHDRCMPLT: c_uint = 0x80044275;  // Header complete
const BIOCSDLT: c_uint = 0x80044278;       // Set data link type
const BIOCPROMISC: c_uint = 0x20004269;    // Promiscuous mode
```

### Data Link Types

- `DLT_IEEE802_11_RADIO` (127): 802.11 + radiotap header
- `DLT_EN10MB` (1): Ethernet (fallback)

## Testing

### Unit Tests

The implementation includes tests for:
- BPF word alignment calculations
- BPF header structure size verification
- Interface name retrieval
- Packet parsing simulation

### Test Execution

```bash
# Run tests on macOS
cargo test --target aarch64-apple-darwin

# Run specific BPF tests
cargo test --target aarch64-apple-darwin test_bpf
```

## Limitations & Considerations

### Current Limitations

1. **Single Packet Return**: Currently returns only the first packet from BPF read
2. **Interface Name Mapping**: Simplified mapping from index to name
3. **Monitor Mode**: Detection implemented but enablement requires additional work
4. **Buffer Size**: Fixed at 32KB (could be made configurable)

### Platform Differences

| Feature | Linux | macOS |
|---------|-------|-------|
| Raw Socket | AF_PACKET | BPF Device |
| Packet Header | None | BPF Header |
| Multiple Packets/Read | No | Yes |
| Alignment Requirements | None | Word-aligned |
| Monitor Mode | nl80211 | Airport/CoreWLAN |

### Security Considerations

- Requires root/admin privileges
- BPF devices are system-level interfaces
- Promiscuous mode affects entire interface
- System Integrity Protection (SIP) may affect functionality

## Future Enhancements

1. **Batch Processing**: Handle multiple packets per BPF read
2. **Dynamic Buffer Sizing**: Adjust based on traffic patterns
3. **CoreWLAN Integration**: Replace placeholder interface functions
4. **Monitor Mode**: Full implementation with Airport utility
5. **Performance Optimization**: Zero-copy operations where possible
6. **Error Recovery**: Enhanced error handling and retry logic

## Usage Examples

### Opening a BPF Socket

```rust
use rawsocks::{open_socket_rx, open_socket_tx};

// Open sockets for interface index 0
let rx_socket = open_socket_rx(0)?;
let tx_socket = open_socket_tx(0)?;
```

### Reading Packets

```rust
use rawsocks::read_bpf_packet;

let packet = read_bpf_packet(rx_socket.as_raw_fd())?;
// packet contains raw 802.11 frame with radiotap header
```

### Writing Packets

```rust
use rawsocks::write_bpf_packet;

let packet_data = build_probe_request(...);
write_bpf_packet(tx_socket.as_raw_fd(), &packet_data)?;
```

## Verification

### Linux Compatibility

The implementation maintains full Linux compatibility:
- No changes to Linux-specific code paths
- Conditional compilation prevents macOS code from affecting Linux builds
- All existing Linux functionality preserved

### Testing Checklist

- [x] BPF device opening
- [x] Interface binding
- [x] Packet reading with header parsing
- [x] Packet writing/injection
- [x] Non-blocking I/O
- [x] Error handling
- [x] Unit tests pass
- [x] Linux build unaffected
- [ ] Integration testing on real hardware
- [ ] Monitor mode testing
- [ ] Performance benchmarking

## References

- [BPF man page](https://www.freebsd.org/cgi/man.cgi?query=bpf&sektion=4)
- [tcpdump source](https://github.com/the-tcpdump-group/tcpdump)
- [libpcap BPF implementation](https://github.com/the-tcpdump-group/libpcap)
- [Apple Developer - Network Extension](https://developer.apple.com/documentation/networkextension)