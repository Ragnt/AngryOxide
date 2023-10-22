extern crate libc;
extern crate nix;
extern crate nl80211;

use libc::{ETH_P_ALL, PACKET_MR_PROMISC, sockaddr_ll, packet_mreq, SOL_PACKET, SO_PRIORITY, ETH_ALEN};
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::sys::socket::{socket, getsockname, SockaddrStorage, AddressFamily, SockFlag, SockType, SockProtocol};
use std::mem;
use std::os::fd::{AsRawFd, OwnedFd};
use std::io;
use anyhow::Result;
use libwifi::Frame;
use radiotap::{Radiotap, Error};

fn determine_key_type(key_information: u16) -> &'static str {
    // Define the bit masks for the relevant bits in the key_information field
    const KEY_ACK: u16 = 1 << 6;
    const KEY_MIC: u16 = 1 << 7;
    const SECURE: u16 = 1 << 8;
    const INSTALL: u16 = 1 << 3;

    match key_information {
        // Check for Message 1 of 4-way handshake
        ki if ki & KEY_ACK != 0 && ki & KEY_MIC == 0 && ki & SECURE == 0 && ki & INSTALL == 0 => {
            "Message 1"
        }
        // Check for Message 2 of 4-way handshake
        ki if ki & KEY_ACK == 0 && ki & KEY_MIC != 0 && ki & SECURE == 0 && ki & INSTALL == 0 => {
            "Message 2"
        }
        // Check for Message 3 of 4-way handshake
        ki if ki & KEY_ACK != 0 && ki & KEY_MIC != 0 && ki & SECURE != 0 && ki & INSTALL != 0 => {
            "Message 3"
        }
        // Check for Message 4 of 4-way handshake
        ki if ki & KEY_ACK == 0 && ki & KEY_MIC != 0 && ki & SECURE != 0 && ki & INSTALL == 0 => {
            "Message 4"
        }
        // Other cases, such as Group Key Handshake, or unrecognized/invalid key information
        _ => "Unknown or Invalid Key Information",
    }
}

pub fn handle_packet(packet: &Vec<u8>) -> Result<(), radiotap::Error> {
    // At first, we look at the
    let radiotap = match Radiotap::from_bytes(packet) {
        Ok(radiotap) => radiotap,
        Err(error) => {
            println!(
                "Couldn't read packet data with Radiotap: {:?}, error {error:?}",
                &packet
            );
            return Err(error);
        }
    };

    let payload = &packet[radiotap.header.length..];
    match libwifi::parse_frame(payload) {
        Ok(frame) => {
            match frame {
                Frame::Beacon(beacon_frame) => {
                    println!("Beacon: {}", beacon_frame.station_info.ssid.unwrap());
                }
                Frame::ProbeRequest(probe_request_frame) => {
                    match probe_request_frame.station_info.ssid {
                        None => {
                            println!("Got a undirected ProbeRequest frame!");
                        }
                        Some(ssid) => {
                            println!("Got a direct ProbeRequest: {}", ssid);
                        }
                    }
                }
                Frame::ProbeResponse(probe_response_frame) => {
                    match probe_response_frame.station_info.ssid {
                        None => {
                            println!("Got a ProbeResponse frame!");
                        }
                        Some(ssid) => {
                            println!("Got a direct ProbeResponse: {}", ssid);
                        }
                    }
                }
                Frame::Authentication(auth_frame) => {
                    println!("Authentication: {}", auth_frame.header.address_1);
                }
                Frame::Deauthentication(deauth_frame) => {
                    println!("Deauthentication: {}", deauth_frame.header.address_1);
                }
                Frame::AssociationRequest(assoc_request_frame) => {
                    println!(
                        "Association: {}",
                        assoc_request_frame.station_info.ssid.unwrap()
                    );
                    // Handle association request frame
                }
                Frame::Data(data_frame) => {
                    println!(
                        "DataFrame: {} => {}",
                        data_frame.header.address_2, data_frame.header.address_1
                    );
                }
                Frame::QosData(data_frame) => {
                    println!(
                        "QoS DataFrame: {} => {} | {}",
                        data_frame.header.address_2,
                        data_frame.header.address_1,
                        data_frame.eapol_key.is_some()
                    );
                    match data_frame.eapol_key {
                        Some(eapol) => {
                            let key_type = determine_key_type(eapol.key_information);
                            println!("Eapol Key: {}", key_type);
                        }
                        None => {}
                    }
                }
                _ => {
                    println!("Got some other kind of frame.");
                }
            }
        }
        Err(err) => {
            println!("Error during parsing :\n{err}");
            if let libwifi::error::Error::Failure(_, data) = err {
                println!("{data:?}")
            }
        }
    };

    Ok(())
}


pub fn open_socket_tx(ifindex: i32) -> Result<OwnedFd, String> {
    let mut saddr: sockaddr_ll = unsafe { mem::zeroed() };
    let mut mrq: packet_mreq = unsafe { mem::zeroed() };
    let prioval = 20;

    let fd_socket_tx = socket(
        AddressFamily::Packet,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::EthAll,
    ).map_err(|e| e.to_string())?;

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
            mem::size_of::<i32>() as libc::socklen_t
        )
    };
    
    saddr.sll_family = libc::AF_PACKET as u16;
    saddr.sll_protocol = (ETH_P_ALL as u16).to_be();
    saddr.sll_ifindex = ifindex;
    saddr.sll_halen = (ETH_ALEN as u8).to_be();
    saddr.sll_pkttype = 3;

    unsafe { 
        libc::bind(
            fd_socket_tx.as_raw_fd(), 
            (&saddr as *const libc::sockaddr_ll).cast(), 
            saddr.sll_addr.len().try_into().unwrap()
        ) 
    };

    let socket_rx_flags = fcntl(fd_socket_tx.as_raw_fd(), FcntlArg::F_GETFL)
        .map_err(|e| e.to_string())?;

    let new_flags = OFlag::from_bits_truncate(socket_rx_flags | OFlag::O_NONBLOCK.bits());
    fcntl(fd_socket_tx.as_raw_fd(), FcntlArg::F_SETFL(new_flags))
        .map_err(|e| e.to_string())?;

    Ok(fd_socket_tx)
}

pub fn open_socket_rx(ifindex: i32) -> Result<OwnedFd, String> {
    let mut saddr: sockaddr_ll = unsafe { mem::zeroed() };
    let mut mrq: packet_mreq = unsafe { mem::zeroed() };
    let prioval = 20;

    // Changed: Updated socket function call to match the C version
    let fd_socket_rx = socket(
        AddressFamily::Packet,
        SockType::Raw , SockFlag::SOCK_CLOEXEC,
        SockProtocol::EthAll,
    ).map_err(|e| e.to_string())?;

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
            mem::size_of::<i32>() as libc::socklen_t
        )
    };

    // New: Ignoring outgoing packets (Linux 4.20 and later)
    #[cfg(target_os = "linux")]
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

    // Changed: Updated saddr.sll_pkttype and bind call to match the C version
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

    let mut buffer = vec![0u8; 4096];
    let packet_len = unsafe {
        libc::read(
            fd_socket_rx.as_raw_fd(),
            buffer.as_mut_ptr() as *mut libc::c_void,
            buffer.len(),
        )
    };

    if packet_len < 0 {
        let error_code = io::Error::last_os_error();
        println!("{}", error_code.to_string());
    }

    buffer.truncate(packet_len as usize);

    Ok(fd_socket_rx)
}


fn read_packet(fd_socket_rx:OwnedFd) -> Result<Vec<u8>, String> {
    // New: Reading packets loop
    let mut buffer = vec![0u8; 2048];
    let packet_len = unsafe {
        libc::read(
            fd_socket_rx.as_raw_fd(),
            buffer.as_mut_ptr() as *mut libc::c_void,
            buffer.len(),
        )
    };

    if packet_len < 0 {
        let error_code = io::Error::last_os_error();
        return Err(error_code.to_string());
    }
    buffer.truncate(packet_len as usize);
    Ok(buffer)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let interfaces = nl80211::Socket::connect()?.get_interfaces_info()?;
    let mut ifindex: Option<i32> = None;
    let interface_name: String = "panda0".to_string();

    for interface in interfaces {
        let mac = interface.mac.unwrap();
        let if_name: String = String::from_utf8(interface.name.unwrap())?;
        let if_id = i32::from(interface.index.unwrap()[0]);

        if if_name.trim_matches(char::from(0)) == interface_name {
            ifindex = Some(if_id);
        
            println!(
                "*{} ({:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}) Index: {}",
                if_name, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], if_id
            );
        } else {
            println!(
                "{} ({:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}) Index: {}",
                if_name, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], if_id
            );
        }
    }

    let rx_socket: OwnedFd;
    let tx_socket: OwnedFd;

    if ifindex.is_some() {
        rx_socket = open_socket_rx(ifindex.unwrap())?;
        tx_socket = open_socket_tx(ifindex.unwrap())?;
        println!("Rx: {}", rx_socket.as_raw_fd());
        println!("Tx: {}", tx_socket.as_raw_fd());
        match read_packet(rx_socket) {
            Ok(packet) => {
                println!("Read packet of length: {}", packet.len());
                match handle_packet(&packet) {
                    Ok(_) => {println!("")}
                    Err(error) => { eprintln!("Error: {error}") }
                }
            },
            Err(e) => eprintln!("Error occurred: {}", e),
        }
    }
    Ok(())
}
