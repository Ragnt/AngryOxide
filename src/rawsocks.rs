use std::os::fd::OwnedFd;

#[cfg(target_os = "linux")]
pub use linux_impl::{open_socket_rx, open_socket_tx};

#[cfg(target_os = "macos")]
pub use macos_impl::{open_socket_rx, open_socket_tx};

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
        mem,
        os::fd::{AsRawFd, OwnedFd},
    };

    use nix::{
        fcntl::{fcntl, FcntlArg, OFlag},
        sys::socket::{socket, AddressFamily, SockFlag, SockType},
    };

    // macOS uses BPF (Berkeley Packet Filter) for raw packet access
    // This is a simplified implementation that would need to be expanded
    // for full functionality
    
    pub fn open_socket_tx(ifindex: i32) -> Result<OwnedFd, String> {
        // On macOS, we need to use BPF devices instead of AF_PACKET
        // This is a placeholder implementation
        Err("macOS implementation for raw TX sockets not yet complete. BPF support needed.".to_string())
    }

    pub fn open_socket_rx(ifindex: i32) -> Result<OwnedFd, String> {
        // On macOS, we need to use BPF devices instead of AF_PACKET
        // This is a placeholder implementation
        Err("macOS implementation for raw RX sockets not yet complete. BPF support needed.".to_string())
    }
}