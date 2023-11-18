//mod netlinker;
mod devices;
mod ntlook;
mod rawsocks;

extern crate libc;
extern crate nix;

use anyhow::Result;
use libc::EXIT_FAILURE;
use ntlook::Sockets;
use radiotap::field::{AntennaSignal, Field};

use crate::devices::{AccessPointData, WiFiDevice, WiFiDeviceList, WiFiDeviceType};
use crate::ntlook::WiFiChannel;
use crate::rawsocks::{open_socket_rx, open_socket_tx};
use libwifi::Frame;

use radiotap::Radiotap;

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crossterm::{execute, ExecutableCommand, cursor::MoveTo, terminal::ClearType, terminal};
use std::io::{stdout};
use std::fmt::Write;

fn epoch_to_string(epoch: u64) -> String {
    match UNIX_EPOCH.checked_add(Duration::from_secs(epoch)) {
        Some(epoch_time) => match SystemTime::now().duration_since(epoch_time) {
            Ok(duration_since) => {
                let elapsed_seconds = duration_since.as_secs();
                if elapsed_seconds > 3600 {
                    format!("{} hours ago", elapsed_seconds / 3600)
                } else if duration_since.as_secs() > 60 {
                    format!("{} hours ago", elapsed_seconds / 60)
                } else {
                    format!("{} seconds ago", elapsed_seconds)
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
    frame_count: u64,
    eapol_count: u64,
    error_count: u64,
    ntsocks: Sockets,
    interface: ntlook::Interface,
}

impl WPOxideRuntime {
    pub fn new() -> Self {
        let ntsocks = ntlook::SocketsBuilder::new().build().unwrap();
        let access_points = WiFiDeviceList::new();
        let unassoc_clients = WiFiDeviceList::new();

        let interface_name: String = "panda0".to_string();
        let mut iface: Option<ntlook::Interface> = None;

        for interface in &ntsocks.interfaces {
            if let Some(ref name) = interface.name {
                if String::from_utf8(name.to_vec())
                    .ok()
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

        let rx_socket = open_socket_rx(iface.clone().unwrap().index.unwrap())
            .expect("Failed to open RX Socket.");
        let tx_socket = open_socket_tx(iface.clone().unwrap().index.unwrap())
            .expect("Failed to open TX Socket.");

        WPOxideRuntime {
            ntsocks,
            rx_socket,
            tx_socket,
            frame_count: 0,
            eapol_count: 0,
            error_count: 0,
            access_points,
            unassoc_clients,
            interface: iface.unwrap(),
        }
    }

    pub fn print_device_lists(&mut self) {
        self.interface = self
            .ntsocks
            .get_interface_info(self.interface.index.unwrap())
            .unwrap()
            .first()
            .unwrap()
            .clone();

        let mut output = String::new();

        // Print access points
        writeln!(output, 
            "Channel: {} | Frames Captured: {} | EAPOL Captured: {} | Errors: {} | APs: {} | Unassoc Clients: {}",
            self.interface.frequency.as_ref().unwrap().channel.as_ref().map_or("None".to_string(), |value| value.to_string()),
            self.frame_count,
            self.eapol_count,
            self.error_count,
            self.access_points.size(),
            self.unassoc_clients.size()
        );
        writeln!(output, 
            "=================================================================================="
        );
        writeln!(output, "\n{:^81}","Access Points:");
        writeln!(output, "{:<15} {:<8} {:<18} {:<35} {:<10}",
            "MAC Address", "RSSI", "Last Seen", "SSID", "Clients"
        );

        let mut devices: Vec<_> = self.access_points.get_devices().iter().collect();
        devices.sort_by(|a, b| b.1.last_recv.cmp(&a.1.last_recv));

        let mut ap_len = 1;
        for (mac, device) in devices {
            if ap_len < 30 {
                if let WiFiDeviceType::AccessPoint(ap_data) = &device.device_type {
                    let unknown = &"Unknown SSID".to_string();
                    let ssid = ap_data.ssid.as_ref().unwrap_or(unknown);
                    let clients_size = ap_data.client_list.clone().size();
                    writeln!(output, "{:<15} {:<8} {:<18} {:<35} {:<10}",
                        mac.to_string(),
                        device.last_signal_strength.value.to_string(),
                        epoch_to_string(device.last_recv).to_string(),
                        ssid,
                        clients_size,
                    );
                    ap_len += 1;
                }
            } else {
                break;
            }
        }
        for _ in 0..(32 - ap_len) {
            writeln!(output);
        }
        writeln!(output, 
            "=================================================================================="
        );
        // Print unassociated clients
        writeln!(output, "\n{:^81}","Unassociated Clients:");
        writeln!(output, 
            "{:<15} {:<8} {:<18} {:<40}",
            "MAC Address", "RSSI", "Last Seen", "Probes"
        );

        let mut client_devices: Vec<_> = self.unassoc_clients.get_devices().iter().collect();
        client_devices.sort_by(|a, b| b.1.last_recv.cmp(&a.1.last_recv));
        let mut client_len = 0;
        for (mac, device) in client_devices {
            if client_len < 15 {
                if let WiFiDeviceType::Station(station_data) = &device.device_type {
                    writeln!(output, "{:<15} {:<8} {:<18} {:<40}",
                        mac.to_string(),
                        device.last_signal_strength.value,
                        epoch_to_string(device.last_recv),
                        station_data.clone().probes_to_string_list(),
                    );
                    client_len += 1;
                }
            } else {
                break;
            }
        }
        for _ in 0..(17 - client_len) {
            writeln!(output);
        }
        writeln!(output, 
            "=================================================================================="
        );
        
        // Clear the terminal
        
        // Move the cursor to the top left of the screen
        execute!(stdout(),MoveTo(0, 0)).unwrap();
        execute!(stdout(),terminal::Clear(ClearType::All)).unwrap();
        print!("{}", output);
    }

    pub fn handle_packet(&mut self, packet: &Vec<u8>) -> Result<(), radiotap::Error> {
        //let raw_packet = packet.clone();
        let radiotap = match Radiotap::from_bytes(packet) {
            Ok(radiotap) => radiotap,
            Err(error) => {
                /* println!(
                    "Couldn't read packet data with Radiotap: {:?}, error {error:?}",
                    &packet
                ); */
                self.error_count += 1;
                return Err(error);
            }
        };
        self.frame_count += 1;
        let payload = &packet[radiotap.header.length..];
        match libwifi::parse_frame(payload) {
            Ok(frame) => match frame {
                Frame::Beacon(beacon_frame) => {
                    //println!("Beacon: {}", beacon_frame.station_info.ssid.unwrap());
                    let bssid = beacon_frame.header.address_3;
                    let signal_strength = radiotap
                        .antenna_signal
                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?); // Replace with actual field for BSSID
                    if bssid.is_real_device() {
                        self.access_points.add_or_update_device(
                            bssid.clone(),
                            WiFiDevice::new_access_point(
                                bssid.clone(),
                                signal_strength,
                                beacon_frame.station_info.ssid,
                            ),
                        )
                    };
                }
                Frame::ProbeRequest(probe_request_frame) => {
                    let signal_strength = radiotap
                        .antenna_signal
                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?);
                    match probe_request_frame.station_info.ssid {
                        None => {
                            //println!("Got a undirected ProbeRequest frame!");
                            let client_mac = probe_request_frame.header.address_2;
                            if client_mac.is_real_device() {
                                self.unassoc_clients.add_or_update_device(
                                    client_mac.clone(),
                                    WiFiDevice::new_unassoc_station(
                                        client_mac.clone(),
                                        signal_strength,
                                        vec![],
                                    ),
                                )
                            };
                        }
                        Some(ssid) => {
                            //println!("Got a direct ProbeRequest: {}", ssid);
                            let client_mac = probe_request_frame.header.address_2;
                            if client_mac.is_real_device() {
                                self.unassoc_clients.add_or_update_device(
                                    client_mac.clone(),
                                    WiFiDevice::new_unassoc_station(
                                        client_mac.clone(),
                                        signal_strength,
                                        vec![ssid],
                                    ),
                                )
                            };
                        }
                    }
                }
                Frame::ProbeResponse(probe_response_frame) => {
                    match probe_response_frame.station_info.ssid {
                        None => {
                            // println!("Got a ProbeResponse frame!");
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
                                        None,
                                    ),
                                )
                            };
                        }
                        Some(ssid) => {
                            //println!("Got a direct ProbeResponse: {}", ssid);
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
                                        Some(ssid),
                                    ),
                                )
                            };
                        }
                    }
                }
                Frame::Authentication(auth_frame) => {
                    //println!("Authentication: {}", auth_frame.header.address_1);
                    let client_mac = auth_frame.header.address_2; // MAC address of the client
                    let bssid = auth_frame.header.address_1; // MAC address of the AP (BSSID)

                    // Add BSSID to aps
                    if bssid.is_real_device() {
                        self.access_points.add_or_update_device(
                            bssid.clone(),
                            WiFiDevice::new_access_point(
                                bssid.clone(),
                                radiotap
                                    .antenna_signal
                                    .unwrap_or(AntennaSignal::from_bytes(&[0u8])?),
                                None,
                            ),
                        )
                    };
                    // Add client to unassoc
                    if client_mac.is_real_device() {
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
                }
                Frame::Deauthentication(deauth_frame) => {
                    //println!("Deauthentication: {}", deauth_frame.header.address_1);
                    let client_mac = deauth_frame.header.address_2; // MAC address of the client
                    let bssid = deauth_frame.header.address_1; // MAC address of the AP (BSSID)

                    if client_mac.is_real_device() {
                        // Process the client (if client is unnassoc)
                    }
                    if bssid.is_real_device() {
                        let client = WiFiDevice::new_station(
                            client_mac,
                            AntennaSignal::from_bytes(&[0u8])?,
                            None,
                        );
                        let ap = WiFiDevice::new_access_point_with_client(
                            bssid.clone(),
                            radiotap
                                .antenna_signal
                                .unwrap_or(AntennaSignal::from_bytes(&[0u8])?),
                            None,
                            vec![client],
                        );
                        self.access_points.add_or_update_device(bssid, ap);
                    };
                }
                Frame::Action(frame) => {
                    //println!("Action Frame: {} => {} / {:?}", frame.header.address_2, frame.header.address_1, frame.category );
                    let source_mac = frame.header.address_2; // MAC address of the source
                    let dest_mac = frame.header.address_1; // MAC address of the destination
                    let from_ds: bool = frame.header.frame_control.from_ds();
                    let to_ds: bool = frame.header.frame_control.to_ds();

                    if source_mac.is_real_device() {
                        // Process the source device
                        if from_ds && !to_ds {
                            // Going to the Client from a AP
                            let mut clients = Vec::new();

                            if dest_mac.is_real_device() {
                                // Make sure this isn't a broadcast or something
                                let client = WiFiDevice::new_station(
                                    dest_mac.clone(),
                                    AntennaSignal::from_bytes(&[0u8])?,
                                    None,
                                );
                                clients.push(client);
                                self.unassoc_clients.remove_device(&dest_mac);
                            }
                            let ap = WiFiDevice::new_access_point_with_client(
                                source_mac.clone(),
                                radiotap
                                    .antenna_signal
                                    .unwrap_or(AntennaSignal::from_bytes(&[0u8])?),
                                None,
                                clients,
                            );
                            self.access_points.add_or_update_device(source_mac, ap);
                        } else if !from_ds && to_ds {
                            // Going to the AP from a client
                            if dest_mac.is_real_device() {
                                // For now I think if the client is sending a broadcast or something we will just ignore.
                                let mut clients = Vec::new();

                                let client = WiFiDevice::new_station(
                                    source_mac.clone(),
                                    radiotap
                                        .antenna_signal
                                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?),
                                    None,
                                );
                                clients.push(client);
                                self.unassoc_clients.remove_device(&source_mac);

                                let ap = WiFiDevice::new_access_point_with_client(
                                    dest_mac.clone(),
                                    AntennaSignal::from_bytes(&[0u8])?,
                                    None,
                                    clients,
                                );
                                self.access_points.add_or_update_device(dest_mac, ap);
                            }
                        }
                    }
                }
                Frame::AssociationRequest(assoc_request_frame) => {
                    /* println!(
                        "Association: {}",
                        assoc_request_frame.station_info.ssid.unwrap()
                    ); */
                    let client_mac = assoc_request_frame.header.address_2; // MAC address of the client
                    let bssid = assoc_request_frame.header.address_1; // MAC address of the AP (BSSID)

                    // Handle client as not yet associated
                    if client_mac.is_real_device() {
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
                    // Handle AP
                    if bssid.is_real_device() {
                        let ap = WiFiDevice::new_access_point_with_client(
                            bssid.clone(),
                            radiotap
                                .antenna_signal
                                .unwrap_or(AntennaSignal::from_bytes(&[0u8])?),
                            None,
                            vec![],
                        );
                        self.access_points.add_or_update_device(bssid, ap);
                    };
                }
                Frame::AssociationResponse(assoc_response_frame) => {
                    /* println!(
                        "Association Resp: {}",
                        assoc_response_frame.station_info.ssid.unwrap()
                    ); */

                    let client_mac = assoc_response_frame.header.address_1; // MAC address of the client
                    let bssid = assoc_response_frame.header.address_2; // MAC address of the AP (BSSID)

                    if bssid.is_real_device() && client_mac.is_real_device() {
                        // Valid devices
                        let mut clients = Vec::new();

                        if assoc_response_frame.status_code != 0 {
                            // Association was successful
                            let client = WiFiDevice::new_station(
                                client_mac.clone(),
                                AntennaSignal::from_bytes(&[0u8])?,
                                Some(assoc_response_frame.association_id),
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
                        );
                        self.access_points.add_or_update_device(bssid, ap);
                    };
                }
                Frame::Data(data_frame) => {
                    /* println!(
                        "DataFrame: {} => {}",
                        data_frame.header.address_2, data_frame.header.address_1
                    ); */
                    let source_mac = data_frame.header.address_2; // MAC address of the source
                    let dest_mac = data_frame.header.address_1; // MAC address of the destination
                    let from_ds: bool = data_frame.header.frame_control.from_ds();
                    let to_ds: bool = data_frame.header.frame_control.to_ds();

                    if source_mac.is_real_device() {
                        // Process the source device
                        if from_ds && !to_ds {
                            // Going to the Client from a AP
                            let mut clients = Vec::new();

                            if dest_mac.is_real_device() {
                                // Make sure this isn't a broadcast or something
                                let client = WiFiDevice::new_station(
                                    dest_mac.clone(),
                                    AntennaSignal::from_bytes(&[0u8])?,
                                    None,
                                );
                                clients.push(client);
                                self.unassoc_clients.remove_device(&dest_mac);
                            }
                            let ap = WiFiDevice::new_access_point_with_client(
                                source_mac.clone(),
                                radiotap
                                    .antenna_signal
                                    .unwrap_or(AntennaSignal::from_bytes(&[0u8])?),
                                None,
                                clients,
                            );
                            self.access_points.add_or_update_device(source_mac, ap);
                        } else if !from_ds && to_ds {
                            // Going to the AP from a client
                            if dest_mac.is_real_device() {
                                // For now I think if the client is sending a broadcast or something we will just ignore.
                                let mut clients = Vec::new();

                                let client = WiFiDevice::new_station(
                                    source_mac.clone(),
                                    radiotap
                                        .antenna_signal
                                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?),
                                    None,
                                );
                                clients.push(client);
                                self.unassoc_clients.remove_device(&source_mac);

                                let ap = WiFiDevice::new_access_point_with_client(
                                    dest_mac.clone(),
                                    AntennaSignal::from_bytes(&[0u8])?,
                                    None,
                                    clients,
                                );
                                self.access_points.add_or_update_device(dest_mac, ap);
                            }
                        }
                    }
                }
                Frame::NullData(data_frame) => {
                    /* println!(
                        "NullData: {} => {}",
                        data_frame.header.address_2, data_frame.header.address_1
                    ); */
                    let source_mac = data_frame.header.address_2; // MAC address of the source
                    let dest_mac = data_frame.header.address_1; // MAC address of the destination
                    let from_ds: bool = data_frame.header.frame_control.from_ds();
                    let to_ds: bool = data_frame.header.frame_control.to_ds();

                    if source_mac.is_real_device() {
                        // Process the source device
                        if from_ds && !to_ds {
                            // Going to the Client from a AP
                            let mut clients = Vec::new();

                            if dest_mac.is_real_device() {
                                // Make sure this isn't a broadcast or something
                                let client = WiFiDevice::new_station(
                                    dest_mac.clone(),
                                    AntennaSignal::from_bytes(&[0u8])?,
                                    None,
                                );
                                clients.push(client);
                                self.unassoc_clients.remove_device(&dest_mac);
                            }
                            let ap = WiFiDevice::new_access_point_with_client(
                                source_mac.clone(),
                                radiotap
                                    .antenna_signal
                                    .unwrap_or(AntennaSignal::from_bytes(&[0u8])?),
                                None,
                                clients,
                            );
                            self.access_points.add_or_update_device(source_mac, ap);
                        } else if !from_ds && to_ds {
                            // Going to the AP from a client
                            if dest_mac.is_real_device() {
                                // For now I think if the client is sending a broadcast or something we will just ignore.
                                let mut clients = Vec::new();

                                let client = WiFiDevice::new_station(
                                    source_mac.clone(),
                                    radiotap
                                        .antenna_signal
                                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?),
                                    None,
                                );
                                clients.push(client);
                                self.unassoc_clients.remove_device(&source_mac);

                                let ap = WiFiDevice::new_access_point_with_client(
                                    dest_mac.clone(),
                                    AntennaSignal::from_bytes(&[0u8])?,
                                    None,
                                    clients,
                                );
                                self.access_points.add_or_update_device(dest_mac, ap);
                            }
                        }
                    }
                }
                Frame::QosNull(data_frame) => {
                    /* println!(
                        "QosNull: {} => {}",
                        data_frame.header.address_2, data_frame.header.address_1
                    ); */
                    let source_mac = data_frame.header.address_2; // MAC address of the source
                    let dest_mac = data_frame.header.address_1; // MAC address of the destination
                    let from_ds: bool = data_frame.header.frame_control.from_ds();
                    let to_ds: bool = data_frame.header.frame_control.to_ds();

                    if source_mac.is_real_device() {
                        // Process the source device
                        if from_ds && !to_ds {
                            // Going to the Client from a AP
                            let mut clients = Vec::new();

                            if dest_mac.is_real_device() {
                                // Make sure this isn't a broadcast or something
                                let client = WiFiDevice::new_station(
                                    dest_mac.clone(),
                                    AntennaSignal::from_bytes(&[0u8])?,
                                    None,
                                );
                                clients.push(client);
                                self.unassoc_clients.remove_device(&dest_mac);
                            }
                            let ap = WiFiDevice::new_access_point_with_client(
                                source_mac.clone(),
                                radiotap
                                    .antenna_signal
                                    .unwrap_or(AntennaSignal::from_bytes(&[0u8])?),
                                None,
                                clients,
                            );
                            self.access_points.add_or_update_device(source_mac, ap);
                        } else if !from_ds && to_ds {
                            // Going to the AP from a client
                            if dest_mac.is_real_device() {
                                // For now I think if the client is sending a broadcast or something we will just ignore.
                                let mut clients = Vec::new();

                                let client = WiFiDevice::new_station(
                                    source_mac.clone(),
                                    radiotap
                                        .antenna_signal
                                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?),
                                    None,
                                );
                                clients.push(client);
                                self.unassoc_clients.remove_device(&source_mac);

                                let ap = WiFiDevice::new_access_point_with_client(
                                    dest_mac.clone(),
                                    AntennaSignal::from_bytes(&[0u8])?,
                                    None,
                                    clients,
                                );
                                self.access_points.add_or_update_device(dest_mac, ap);
                            }
                        }
                    }
                }
                Frame::QosData(data_frame) => {
                    if let Some(eapol) = data_frame.eapol_key {
                        let key_type = eapol.clone().determine_key_type();
                        self.eapol_count += 1;
                        /* println!(
                            "QoS DataFrame: {} => {} | EAPOL {}",
                            data_frame.header.address_2, data_frame.header.address_1, key_type
                        ); */
                    } else {
                        /* println!(
                            "QoS DataFrame: {} => {}",
                            data_frame.header.address_2, data_frame.header.address_1
                        ); */
                    }
                    let source_mac = data_frame.header.address_2; // MAC address of the source
                    let dest_mac = data_frame.header.address_1; // MAC address of the destination
                    let from_ds: bool = data_frame.header.frame_control.from_ds();
                    let to_ds: bool = data_frame.header.frame_control.to_ds();

                    if source_mac.is_real_device() {
                        // Process the source device
                        if from_ds && !to_ds {
                            // Going to the Client from a AP
                            let mut clients = Vec::new();

                            if dest_mac.is_real_device() {
                                // Make sure this isn't a broadcast or something
                                let client = WiFiDevice::new_station(
                                    dest_mac.clone(),
                                    AntennaSignal::from_bytes(&[0u8])?,
                                    None,
                                );
                                clients.push(client);
                                self.unassoc_clients.remove_device(&dest_mac);
                            }
                            let ap = WiFiDevice::new_access_point_with_client(
                                source_mac.clone(),
                                radiotap
                                    .antenna_signal
                                    .unwrap_or(AntennaSignal::from_bytes(&[0u8])?),
                                None,
                                clients,
                            );
                            self.access_points.add_or_update_device(source_mac, ap);
                        } else if !from_ds && to_ds {
                            // Going to the AP from a client
                            if dest_mac.is_real_device() {
                                // For now I think if the client is sending a broadcast or something we will just ignore.
                                let mut clients = Vec::new();

                                let client = WiFiDevice::new_station(
                                    source_mac.clone(),
                                    radiotap
                                        .antenna_signal
                                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?),
                                    None,
                                );
                                clients.push(client);
                                self.unassoc_clients.remove_device(&source_mac);

                                let ap = WiFiDevice::new_access_point_with_client(
                                    dest_mac.clone(),
                                    AntennaSignal::from_bytes(&[0u8])?,
                                    None,
                                    clients,
                                );
                                self.access_points.add_or_update_device(dest_mac, ap);
                            }
                        }
                    }
                }
                Frame::Rts(frame) => {
                    /* println!("RTS: {} => {}", frame.source, frame.destination); */
                    let source_mac = frame.source; // MAC address of the source
                    let dest_mac = frame.destination; // MAC address of the destination
                    let from_ds: bool = frame.frame_control.from_ds();
                    let to_ds: bool = frame.frame_control.to_ds();

                    if source_mac.is_real_device() {
                        // Process the source device
                        if from_ds && !to_ds {
                            // Going to the Client from a AP
                            let mut clients = Vec::new();

                            if dest_mac.is_real_device() {
                                // Make sure this isn't a broadcast or something
                                let client = WiFiDevice::new_station(
                                    dest_mac.clone(),
                                    AntennaSignal::from_bytes(&[0u8])?,
                                    None,
                                );
                                clients.push(client);
                                self.unassoc_clients.remove_device(&dest_mac);
                            }
                            let ap = WiFiDevice::new_access_point_with_client(
                                source_mac.clone(),
                                radiotap
                                    .antenna_signal
                                    .unwrap_or(AntennaSignal::from_bytes(&[0u8])?),
                                None,
                                clients,
                            );
                            self.access_points.add_or_update_device(source_mac, ap);
                        } else if !from_ds && to_ds {
                            // Going to the AP from a client
                            if dest_mac.is_real_device() {
                                // For now I think if the client is sending a broadcast or something we will just ignore.
                                let mut clients = Vec::new();

                                let client = WiFiDevice::new_station(
                                    source_mac.clone(),
                                    radiotap
                                        .antenna_signal
                                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?),
                                    None,
                                );
                                clients.push(client);
                                self.unassoc_clients.remove_device(&source_mac);

                                let ap = WiFiDevice::new_access_point_with_client(
                                    dest_mac.clone(),
                                    AntennaSignal::from_bytes(&[0u8])?,
                                    None,
                                    clients,
                                );
                                self.access_points.add_or_update_device(dest_mac, ap);
                            }
                        }
                    }
                }
                Frame::Cts(frame) => {
                    //println!("CTS: => {}", frame.destination);
                    let dest_mac = frame.destination;
                    // Not really doing anything with these yet...
                }
                Frame::Ack(frame) => {
                    //println!("Ack: => {}", frame.destination);
                    let dest_mac = frame.destination;
                    let from_ds: bool = frame.frame_control.from_ds();
                    let to_ds: bool = frame.frame_control.to_ds();

                    // Not really doing anything with these yet...
                }
                Frame::BlockAck(frame) => {
                    //println!("BlockAck: {} => {}", frame.source, frame.destination);
                    let source_mac = frame.source; // MAC address of the source
                    let dest_mac = frame.destination; // MAC address of the destination
                    let from_ds: bool = frame.frame_control.from_ds();
                    let to_ds: bool = frame.frame_control.to_ds();

                    if source_mac.is_real_device() {
                        // Process the source device
                        if from_ds && !to_ds {
                            // Going to the Client from a AP
                            let mut clients = Vec::new();

                            if dest_mac.is_real_device() {
                                // Make sure this isn't a broadcast or something
                                let client = WiFiDevice::new_station(
                                    dest_mac.clone(),
                                    AntennaSignal::from_bytes(&[0u8])?,
                                    None,
                                );
                                clients.push(client);
                                self.unassoc_clients.remove_device(&dest_mac);
                            }
                            let ap = WiFiDevice::new_access_point_with_client(
                                source_mac.clone(),
                                radiotap
                                    .antenna_signal
                                    .unwrap_or(AntennaSignal::from_bytes(&[0u8])?),
                                None,
                                clients,
                            );
                            self.access_points.add_or_update_device(source_mac, ap);
                        } else if !from_ds && to_ds {
                            // Going to the AP from a client
                            if dest_mac.is_real_device() {
                                // For now I think if the client is sending a broadcast or something we will just ignore.
                                let mut clients = Vec::new();

                                let client = WiFiDevice::new_station(
                                    source_mac.clone(),
                                    radiotap
                                        .antenna_signal
                                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?),
                                    None,
                                );
                                clients.push(client);
                                self.unassoc_clients.remove_device(&source_mac);

                                let ap = WiFiDevice::new_access_point_with_client(
                                    dest_mac.clone(),
                                    AntennaSignal::from_bytes(&[0u8])?,
                                    None,
                                    clients,
                                );
                                self.access_points.add_or_update_device(dest_mac, ap);
                            }
                        }
                    }
                }
                Frame::BlockAckRequest(frame) => {
                    //println!("BlockAckRequest: {} => {}", frame.source, frame.destination);
                    let source_mac = frame.source; // MAC address of the source
                    let dest_mac = frame.destination; // MAC address of the destination
                    let from_ds: bool = frame.frame_control.from_ds();
                    let to_ds: bool = frame.frame_control.to_ds();

                    if source_mac.is_real_device() {
                        // Process the source device
                        if from_ds && !to_ds {
                            // Going to the Client from a AP
                            let mut clients = Vec::new();

                            if dest_mac.is_real_device() {
                                // Make sure this isn't a broadcast or something
                                let client = WiFiDevice::new_station(
                                    dest_mac.clone(),
                                    AntennaSignal::from_bytes(&[0u8])?,
                                    None,
                                );
                                clients.push(client);
                                self.unassoc_clients.remove_device(&dest_mac);
                            }
                            let ap = WiFiDevice::new_access_point_with_client(
                                source_mac.clone(),
                                radiotap
                                    .antenna_signal
                                    .unwrap_or(AntennaSignal::from_bytes(&[0u8])?),
                                None,
                                clients,
                            );
                            self.access_points.add_or_update_device(source_mac, ap);
                        } else if !from_ds && to_ds {
                            // Going to the AP from a client
                            if dest_mac.is_real_device() {
                                // For now I think if the client is sending a broadcast or something we will just ignore.
                                let mut clients = Vec::new();

                                let client = WiFiDevice::new_station(
                                    source_mac.clone(),
                                    radiotap
                                        .antenna_signal
                                        .unwrap_or(AntennaSignal::from_bytes(&[0u8])?),
                                    None,
                                );
                                clients.push(client);
                                self.unassoc_clients.remove_device(&source_mac);

                                let ap = WiFiDevice::new_access_point_with_client(
                                    dest_mac.clone(),
                                    AntennaSignal::from_bytes(&[0u8])?,
                                    None,
                                    clients,
                                );
                                self.access_points.add_or_update_device(dest_mac, ap);
                            }
                        }
                    }
                }
            },
            Err(err) => {
                //println!("Error during parsing :\n{err}");
                if let libwifi::error::Error::Failure(_, data) = err {
                    self.error_count += 1;
                    //println!("{data:?}")
                }
            }
        };

        Ok(())
    }

    pub fn read_packet(&mut self) -> Result<Vec<u8>, String> {
        // New: Reading packets loop
        let mut buffer = vec![0u8; 2048];
        let packet_len = unsafe {
            libc::read(
                self.rx_socket.as_raw_fd(),
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
            )
        };

        if packet_len < 0 {
            self.error_count += 1;
            let error_code = io::Error::last_os_error();
            return Err(error_code.to_string());
        }
        buffer.truncate(packet_len as usize);
        Ok(buffer)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut oxide = WPOxideRuntime::new();

    println!("============ INTERFACES ============");
    oxide.ntsocks.print_interfaces();
    println!("====================================");
    println!();

    let iface = oxide.interface.clone();
    let idx = iface.index.unwrap();
    let interface_name =
        String::from_utf8(iface.name.unwrap()).expect("cannot get interface name from bytes.");

    println!("Setting {} down.", interface_name);
    oxide.ntsocks.set_interface_down(idx)?;

    println!("Randomizing {} mac.", interface_name);
    oxide.ntsocks.set_interface_mac_random(idx)?;

    println!("Setting {} monitor mode.", interface_name);
    oxide.ntsocks.set_interface_monitor(idx)?;

    println!("Setting {} up.", interface_name);
    oxide.ntsocks.set_interface_up(idx)?;

    println!("Setting {} channel to 1", interface_name);
    oxide.ntsocks.set_interface_chan(idx, 1)?;

    oxide.ntsocks.print_interface(idx);
    println!();
    let duration = Duration::from_secs(1);
    thread::sleep(duration);

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    println!("========== Listening for Frame ===========");

    let mut last_channel_time = Instant::now();
    let mut last_status_time = Instant::now();
    let channel_interval = Duration::from_secs(1); // Set the interval as needed
    let status_interval = Duration::from_millis(500); // Set the interval as needed

    let hop_chans: [u8; 3] = [1, 6, 11];
    let mut cycle_iter = hop_chans.iter().cycle();

    while running.load(Ordering::SeqCst) {
        // Handle Channel Hopping
        if last_channel_time.elapsed() >= channel_interval {
            last_channel_time = Instant::now();
            if let Some(number) = cycle_iter.next() {
                oxide.ntsocks.set_interface_chan(idx, *number)?;
            }
        }
        // Handle Status Messages
        if last_status_time.elapsed() >= status_interval {
            last_status_time = Instant::now();
            oxide.print_device_lists();
        }
        match oxide.read_packet() {
            Ok(packet) => match oxide.handle_packet(&packet) {
                Ok(_) => {}
                Err(error) => {
                    eprintln!("Error: {error}")
                }
            },
            Err(e) => eprintln!("Error occurred: {}", e),
        }
    }
    println!();
    println!("Setting {} down.", interface_name);
    oxide.ntsocks.set_interface_down(idx)?;

    println!("Setting {} to station mode.", interface_name);
    oxide.ntsocks.set_interface_station(idx)?;
    Ok(())
}
