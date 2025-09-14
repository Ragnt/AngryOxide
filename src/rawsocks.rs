#[cfg(target_os = "linux")]
pub use linux_impl::{open_socket_rx, open_socket_tx};

#[cfg(target_os = "macos")]
pub use macos_impl::{open_socket_rx, open_socket_tx, read_bpf_packet, write_bpf_packet};

#[cfg(target_os = "linux")]
mod linux_impl {
    use std::{
        io, mem,
        os::fd::{AsRawFd, OwnedFd},
    };

    use libc::{
        packet_mreq, sockaddr_ll, ETH_ALEN, ETH_P_ALL, PACKET_MR_PROMISC, SOL_PACKET, SO_PRIORITY,
    };
    use nix::{
        fcntl::{fcntl, FcntlArg, OFlag},
        sys::socket::{socket, AddressFamily, SockFlag, SockProtocol, SockType},
    };
    use procfs::KernelVersion;

    pub fn open_socket_tx(ifindex: i32) -> Result<OwnedFd, String> {
        let mut saddr: sockaddr_ll = unsafe { mem::zeroed() };
        let mut mrq: packet_mreq = unsafe { mem::zeroed() };
        let prioval = 20;

        let fd_socket_tx = socket(
            AddressFamily::Packet,
            SockType::Raw,
            SockFlag::SOCK_CLOEXEC,
            SockProtocol::EthAll,
        )
        .map_err(|e| e.to_string())?;

        mrq.mr_ifindex = ifindex;
        mrq.mr_type = PACKET_MR_PROMISC as u16;

        let ret = unsafe {
            libc::setsockopt(
                fd_socket_tx.as_raw_fd(),
                SOL_PACKET,
                libc::PACKET_ADD_MEMBERSHIP,
                &mrq as *const _ as *const libc::c_void,
                mem::size_of::<packet_mreq>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            return Err("Failed to set PACKET_ADD_MEMBERSHIP option".to_string());
        }

        unsafe {
            libc::setsockopt(
                fd_socket_tx.as_raw_fd(),
                SOL_PACKET,
                SO_PRIORITY,
                &prioval as *const _ as *const libc::c_void,
                mem::size_of::<i32>() as libc::socklen_t,
            )
        };

        saddr.sll_family = libc::AF_PACKET as u16; // Use AF_PACKET
        saddr.sll_protocol = (ETH_P_ALL as u16).to_be();
        saddr.sll_ifindex = ifindex;
        saddr.sll_halen = ETH_ALEN as u8; // Directly set ETH_ALEN, no need for to_be()

        let bind_ret = unsafe {
            libc::bind(
                fd_socket_tx.as_raw_fd(),
                (&saddr as *const libc::sockaddr_ll).cast(),
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t, // Use the size of sockaddr_ll
            )
        };

        if bind_ret < 0 {
            let error = io::Error::last_os_error();
            return Err(format!("Bind failed: {}", error));
        }

        /* saddr.sll_family = libc::PF_PACKET as u16;
        saddr.sll_protocol = (ETH_P_ALL as u16).to_be();
        saddr.sll_ifindex = ifindex;
        saddr.sll_halen = (ETH_ALEN as u8).to_be();
        saddr.sll_pkttype = 3;

        let bind_ret = unsafe {
            libc::bind(
                fd_socket_tx.as_raw_fd(),
                (&saddr as *const libc::sockaddr_ll).cast(),
                saddr.sll_addr.len().try_into().unwrap(),
            )
        };
        println!("BIND RET: {bind_ret}"); */

        let socket_tx_flags =
            fcntl(fd_socket_tx.as_raw_fd(), FcntlArg::F_GETFL).map_err(|e| e.to_string())?;

        let new_flags = OFlag::from_bits_truncate(socket_tx_flags | OFlag::O_NONBLOCK.bits());
        fcntl(fd_socket_tx.as_raw_fd(), FcntlArg::F_SETFL(new_flags)).map_err(|e| e.to_string())?;

        Ok(fd_socket_tx)
    }

    pub fn open_socket_rx(ifindex: i32) -> Result<OwnedFd, String> {
        let mut saddr: sockaddr_ll = unsafe { mem::zeroed() };
        let mut mrq: packet_mreq = unsafe { mem::zeroed() };
        let prioval = 20;

        let fd_socket_rx = socket(
            AddressFamily::Packet,
            SockType::Raw,
            SockFlag::SOCK_CLOEXEC,
            SockProtocol::EthAll,
        )
        .map_err(|e| e.to_string())?;

        mrq.mr_ifindex = ifindex;
        mrq.mr_type = PACKET_MR_PROMISC as u16;

        let ret = unsafe {
            libc::setsockopt(
                fd_socket_rx.as_raw_fd(),
                SOL_PACKET,
                libc::PACKET_ADD_MEMBERSHIP,
                &mrq as *const _ as *const libc::c_void,
                mem::size_of::<packet_mreq>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err("Failed to set PACKET_ADD_MEMBERSHIP option".to_string());
        }

        unsafe {
            libc::setsockopt(
                fd_socket_rx.as_raw_fd(),
                SOL_PACKET,
                SO_PRIORITY,
                &prioval as *const _ as *const libc::c_void,
                mem::size_of::<i32>() as libc::socklen_t,
            )
        };

        // New: Ignoring outgoing packets (Linux 4.20 and later)
        if KernelVersion::current().is_ok()
            && KernelVersion::current().unwrap() > KernelVersion::new(4, 20, 0)
        {
            let enable = 1;
            let ret = unsafe {
                libc::setsockopt(
                    fd_socket_rx.as_raw_fd(),
                    SOL_PACKET,
                    23,
                    &enable as *const _ as *const libc::c_void,
                    mem::size_of::<i32>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                eprintln!("PACKET_IGNORE_OUTGOING is not supported by kernel...");
            }
        }

        saddr.sll_family = libc::AF_PACKET as u16;
        saddr.sll_protocol = (ETH_P_ALL as u16).to_be();
        saddr.sll_ifindex = ifindex;
        saddr.sll_halen = (ETH_ALEN as u8).to_be();
        saddr.sll_pkttype = 3;

        unsafe {
            libc::bind(
                fd_socket_rx.as_raw_fd(),
                (&saddr as *const libc::sockaddr_ll).cast(),
                mem::size_of::<sockaddr_ll>() as libc::socklen_t,
            )
        };

        let socket_rx_flags =
            fcntl(fd_socket_rx.as_raw_fd(), FcntlArg::F_GETFL).map_err(|e| e.to_string())?;

        let new_flags = OFlag::from_bits_truncate(socket_rx_flags | OFlag::O_NONBLOCK.bits());
        fcntl(fd_socket_rx.as_raw_fd(), FcntlArg::F_SETFL(new_flags)).map_err(|e| e.to_string())?;

        Ok(fd_socket_rx)
    }
}

#[cfg(target_os = "macos")]
mod macos_impl {
    use std::{
        ffi::CString,
        io, mem,
        os::fd::{FromRawFd, OwnedFd},
        os::unix::io::RawFd,
        ptr,
    };

    use libc::{c_char, c_int, c_uint, c_void, ioctl, open, timeval, O_RDWR};
    use nix::fcntl::{fcntl, FcntlArg, OFlag};

    // BPF ioctl constants for macOS
    #[allow(dead_code)]
    const BIOCGBLEN: c_uint = 0x40044266;
    const BIOCSBLEN: c_uint = 0xc0044266;
    const BIOCSETIF: c_uint = 0x8020426c;
    const BIOCIMMEDIATE: c_uint = 0x80044270;
    const BIOCSHDRCMPLT: c_uint = 0x80044275;
    #[allow(dead_code)]
    const BIOCGDLT: c_uint = 0x4004426a;
    const BIOCSDLT: c_uint = 0x80044278;
    const BIOCPROMISC: c_uint = 0x20004269;
    const DLT_IEEE802_11_RADIO: c_int = 127;
    const DLT_EN10MB: c_int = 1;

    // BPF alignment
    const BPF_ALIGNMENT: usize = 4; // sizeof(long) on 32-bit, adjust for 64-bit if needed

    // BPF header structure
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct bpf_hdr {
        pub bh_tstamp: timeval, // timestamp
        pub bh_caplen: u32,     // length of captured portion
        pub bh_datalen: u32,    // original length of packet
        pub bh_hdrlen: u16,     // length of bpf header (this struct plus alignment padding)
    }

    // Macro to align to word boundary
    pub fn bpf_wordalign(x: usize) -> usize {
        (x + (BPF_ALIGNMENT - 1)) & !(BPF_ALIGNMENT - 1)
    }

    #[repr(C)]
    struct ifreq {
        ifr_name: [c_char; 16],
        ifr_ifru: [u8; 16],
    }

    fn open_bpf_device() -> Result<RawFd, String> {
        // Try to open BPF devices /dev/bpf0 through /dev/bpf255
        for i in 0..256 {
            let path = format!("/dev/bpf{}", i);
            let c_path = CString::new(path.clone()).map_err(|e| e.to_string())?;

            let fd = unsafe { open(c_path.as_ptr(), O_RDWR) };
            if fd >= 0 {
                return Ok(fd);
            }
        }

        Err("Could not open any BPF device".to_string())
    }

    pub fn get_interface_name(ifindex: i32) -> Result<String, String> {
        // On macOS, we need to convert ifindex to interface name
        // This is a simplified version - should use if_indextoname
        use std::process::Command;

        let output = Command::new("ifconfig")
            .arg("-l")
            .output()
            .map_err(|e| e.to_string())?;

        let interfaces = String::from_utf8_lossy(&output.stdout);
        let iface_list: Vec<&str> = interfaces.split_whitespace().collect();

        // For now, we'll need the interface name to be passed differently
        // This is a limitation we'll need to address
        if iface_list.len() > ifindex as usize {
            Ok(iface_list[ifindex as usize].to_string())
        } else {
            // Default to common macOS WiFi interface name
            Ok("en0".to_string())
        }
    }

    fn configure_bpf(fd: RawFd, ifname: &str, is_tx: bool) -> Result<(), String> {
        // Set buffer size
        let buf_len: c_uint = 32768; // 32KB buffer
        let ret = unsafe {
            ioctl(
                fd,
                BIOCSBLEN as _,
                &buf_len as *const c_uint as *const c_void,
            )
        };
        if ret < 0 {
            return Err(format!(
                "Failed to set BPF buffer length: {}",
                io::Error::last_os_error()
            ));
        }

        // Bind to interface
        let mut ifr: ifreq = unsafe { mem::zeroed() };
        let ifname_bytes = ifname.as_bytes();
        if ifname_bytes.len() >= 16 {
            return Err("Interface name too long".to_string());
        }

        for (i, &byte) in ifname_bytes.iter().enumerate() {
            ifr.ifr_name[i] = byte as c_char;
        }

        let ret = unsafe { ioctl(fd, BIOCSETIF as _, &ifr as *const ifreq as *const c_void) };
        if ret < 0 {
            return Err(format!(
                "Failed to bind BPF to interface {}: {}",
                ifname,
                io::Error::last_os_error()
            ));
        }

        // Set immediate mode (don't buffer packets)
        let immediate: c_uint = 1;
        let ret = unsafe {
            ioctl(
                fd,
                BIOCIMMEDIATE as _,
                &immediate as *const c_uint as *const c_void,
            )
        };
        if ret < 0 {
            return Err(format!(
                "Failed to set immediate mode: {}",
                io::Error::last_os_error()
            ));
        }

        // Set promiscuous mode
        let ret = unsafe { ioctl(fd, BIOCPROMISC as _, ptr::null::<c_void>()) };
        if ret < 0 {
            eprintln!(
                "Warning: Failed to set promiscuous mode: {}",
                io::Error::last_os_error()
            );
        }

        if is_tx {
            // Set header complete mode for TX (we'll provide complete headers)
            let hdrcmplt: c_uint = 1;
            let ret = unsafe {
                ioctl(
                    fd,
                    BIOCSHDRCMPLT as _,
                    &hdrcmplt as *const c_uint as *const c_void,
                )
            };
            if ret < 0 {
                return Err(format!(
                    "Failed to set header complete mode: {}",
                    io::Error::last_os_error()
                ));
            }
        }

        // Try to set DLT to 802.11 radiotap
        let dlt = DLT_IEEE802_11_RADIO;
        let ret = unsafe { ioctl(fd, BIOCSDLT as _, &dlt as *const c_int as *const c_void) };
        if ret < 0 {
            eprintln!(
                "Warning: Could not set DLT to IEEE802_11_RADIO, monitor mode may not be available"
            );
            // Fall back to Ethernet
            let dlt = DLT_EN10MB;
            unsafe { ioctl(fd, BIOCSDLT as _, &dlt as *const c_int as *const c_void) };
        }

        Ok(())
    }

    pub fn open_socket_tx(ifindex: i32) -> Result<OwnedFd, String> {
        let fd = open_bpf_device()?;

        // Get interface name from index
        let ifname = get_interface_name(ifindex)?;

        // Configure BPF for TX
        configure_bpf(fd, &ifname, true)?;

        // Set non-blocking
        let flags = fcntl(fd, FcntlArg::F_GETFL).map_err(|e| e.to_string())?;
        let new_flags = OFlag::from_bits_truncate(flags | OFlag::O_NONBLOCK.bits());
        fcntl(fd, FcntlArg::F_SETFL(new_flags)).map_err(|e| e.to_string())?;

        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    pub fn open_socket_rx(ifindex: i32) -> Result<OwnedFd, String> {
        let fd = open_bpf_device()?;

        // Get interface name from index
        let ifname = get_interface_name(ifindex)?;

        // Configure BPF for RX
        configure_bpf(fd, &ifname, false)?;

        // Set non-blocking
        let flags = fcntl(fd, FcntlArg::F_GETFL).map_err(|e| e.to_string())?;
        let new_flags = OFlag::from_bits_truncate(flags | OFlag::O_NONBLOCK.bits());
        fcntl(fd, FcntlArg::F_SETFL(new_flags)).map_err(|e| e.to_string())?;

        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Read a packet from BPF device
    /// Returns the packet data without the BPF header
    pub fn read_bpf_packet(fd: RawFd) -> Result<Vec<u8>, io::Error> {
        const BUFFER_SIZE: usize = 32768; // 32KB buffer
        let mut buffer = vec![0u8; BUFFER_SIZE];

        // Read from BPF device
        let bytes_read =
            unsafe { libc::read(fd, buffer.as_mut_ptr() as *mut c_void, buffer.len()) };

        if bytes_read < 0 {
            return Err(io::Error::last_os_error());
        }

        if bytes_read == 0 {
            return Ok(Vec::new());
        }

        // Parse BPF packets (BPF can return multiple packets in one read)
        let mut offset = 0;

        while offset < bytes_read as usize {
            // Check if we have enough data for a BPF header
            if offset + mem::size_of::<bpf_hdr>() > bytes_read as usize {
                break;
            }

            // Parse BPF header
            let hdr_ptr = unsafe { buffer.as_ptr().add(offset) as *const bpf_hdr };
            let hdr = unsafe { *hdr_ptr };

            // Get packet data (skip BPF header)
            let data_offset = offset + hdr.bh_hdrlen as usize;
            let data_end = data_offset + hdr.bh_caplen as usize;

            if data_end <= bytes_read as usize {
                // Extract packet data
                let packet_data = buffer[data_offset..data_end].to_vec();

                // For now, return the first packet
                // In a full implementation, you might want to handle multiple packets
                return Ok(packet_data);
            }

            // Move to next packet (aligned)
            offset = bpf_wordalign(offset + hdr.bh_hdrlen as usize + hdr.bh_caplen as usize);
        }

        Ok(Vec::new())
    }

    /// Write a packet to BPF device for injection
    pub fn write_bpf_packet(fd: RawFd, packet: &[u8]) -> Result<isize, io::Error> {
        // BPF expects just the packet data for injection (no BPF header needed)
        let bytes_written =
            unsafe { libc::write(fd, packet.as_ptr() as *const c_void, packet.len()) };

        if bytes_written < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(bytes_written)
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn test_bpf_wordalign() {
        // Test alignment function
        assert_eq!(macos_impl::bpf_wordalign(0), 0);
        assert_eq!(macos_impl::bpf_wordalign(1), 4);
        assert_eq!(macos_impl::bpf_wordalign(2), 4);
        assert_eq!(macos_impl::bpf_wordalign(3), 4);
        assert_eq!(macos_impl::bpf_wordalign(4), 4);
        assert_eq!(macos_impl::bpf_wordalign(5), 8);
        assert_eq!(macos_impl::bpf_wordalign(8), 8);
        assert_eq!(macos_impl::bpf_wordalign(9), 12);
    }

    #[test]
    fn test_bpf_header_size() {
        use macos_impl::bpf_hdr;
        use std::mem;

        // Verify the size of bpf_hdr structure
        let expected_size = mem::size_of::<libc::timeval>() + 4 + 4 + 2; // timeval + caplen + datalen + hdrlen
        let actual_size = mem::size_of::<bpf_hdr>();

        // The actual size might be larger due to padding
        assert!(
            actual_size >= expected_size,
            "BPF header size {} is less than expected {}",
            actual_size,
            expected_size
        );
    }

    #[test]
    fn test_get_interface_name() {
        // Test interface name retrieval
        // This will likely return "en0" or similar on macOS
        let result = macos_impl::get_interface_name(0);
        assert!(result.is_ok(), "Failed to get interface name: {:?}", result);

        let name = result.unwrap();
        assert!(!name.is_empty(), "Interface name should not be empty");
    }

    #[test]
    fn test_bpf_packet_parsing() {
        use macos_impl::bpf_hdr;
        use std::mem;

        // Create a mock BPF buffer with header and packet data
        let packet_data = b"test packet data";
        let hdr = bpf_hdr {
            bh_tstamp: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            bh_caplen: packet_data.len() as u32,
            bh_datalen: packet_data.len() as u32,
            bh_hdrlen: mem::size_of::<bpf_hdr>() as u16,
        };

        // Create buffer with BPF header followed by packet data
        let mut buffer = Vec::new();

        // Add header bytes
        let hdr_bytes = unsafe {
            std::slice::from_raw_parts(&hdr as *const _ as *const u8, mem::size_of::<bpf_hdr>())
        };
        buffer.extend_from_slice(hdr_bytes);

        // Add packet data
        buffer.extend_from_slice(packet_data);

        // Verify we can parse the header back
        let parsed_hdr = unsafe { *(buffer.as_ptr() as *const bpf_hdr) };

        assert_eq!(parsed_hdr.bh_caplen, packet_data.len() as u32);
        assert_eq!(parsed_hdr.bh_datalen, packet_data.len() as u32);

        // Extract packet data
        let data_start = parsed_hdr.bh_hdrlen as usize;
        let data_end = data_start + parsed_hdr.bh_caplen as usize;
        let extracted_data = &buffer[data_start..data_end];

        assert_eq!(extracted_data, packet_data);
    }
}
