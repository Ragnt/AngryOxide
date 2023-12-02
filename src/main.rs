mod ascii;
mod attack;
mod auth;
mod devices;
mod ntlook;
mod rawsocks;
mod status;
mod tx;
mod ui;

extern crate libc;
extern crate nix;

use anyhow::Result;
use attack::{
    attack_association_request, attack_authentication_from_ap, attack_authentication_from_client,
    attack_beacon, attack_probe_request, attack_probe_request_direct, attack_probe_response,
};

use crossterm::cursor::position;
use crossterm::event::{poll, read, self, KeyCode, Event};
use crossterm::terminal::{enable_raw_mode, disable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen, self};
use libc::{EXIT_FAILURE, EXIT_SUCCESS};
use libwifi::frame::components::{MacAddress, RsnAkmSuite, RsnCipherSuite, WpaAkmSuite};
use libwifi::frame::{DataFrame, NullDataFrame};
use nix::unistd::geteuid;

use ntlook::{
    get_interface_info_name, set_interface_chan, set_interface_down, set_interface_mac,
    set_interface_monitor, set_interface_station, set_interface_up,
};

use radiotap::field::{AntennaSignal, Field};
use radiotap::Radiotap;
use rawsocks::{open_socket_rx, open_socket_tx};

use crate::ascii::get_art;
use crate::auth::HandshakeStorage;
use crate::devices::{APFlags, AccessPoint, Station, WiFiDeviceList};
use crate::status::*;
use crate::ui::{default_ui, print_ui};

use libwifi::{Addresses, Frame};

use crossterm::{cursor::Hide, cursor::Show, execute};

use std::io;
use std::io::stdout;
use std::os::fd::{AsRawFd, OwnedFd};
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "WPOxide")]
#[command(author = "Ragnt")]
#[command(version = "0.1.0")]
#[command(about = "Does awesome things... with wifi.", long_about = None)]
struct Arguments {
    #[arg(short, long)]
    /// Interface to use.
    interface: String,
    #[arg(short, long, default_values_t = [1, 6, 11]) ]
    /// Optional list of channels to scan.
    channels: Vec<u8>,
}

pub struct UiState {
    menu: u8,
    paused: bool,
    ap_sort: u8,
    cl_sort: u8,
    hs_sort: u8,
    sort_reverse: bool,
}

impl UiState {
    pub fn menu_next(&mut self) -> u8{
        if self.menu == 3 {
            self.menu = 0;
            return self.menu;
        }
        self.menu += 1;
        self.menu
    }

    pub fn menu_back(&mut self) -> u8{
        if self.menu == 0 {
            self.menu = 3;
            return self.menu;
        }
        self.menu -= 1;
        self.menu
    }

    pub fn ap_sort_next(&mut self) -> u8{
        if self.ap_sort == 5 {
            self.ap_sort = 0;
            return self.ap_sort;
        }
        self.ap_sort += 1;
        self.ap_sort
    }

    pub fn cl_sort_next(&mut self) -> u8{
        if self.cl_sort == 1 {
            self.cl_sort = 0;
            return self.cl_sort;
        }
        self.cl_sort += 1;
        self.cl_sort
    }

    pub fn hs_sort_next(&mut self) -> u8{
        if self.hs_sort == 4 {
            self.hs_sort = 0;
            return self.hs_sort;
        }
        self.hs_sort += 1;
        self.hs_sort
    }

    pub fn toggle_pause(&mut self) {
        self.paused = !self.paused
    }

    pub fn toggle_reverse(&mut self) {
        self.sort_reverse = !self.sort_reverse
    }
}

#[derive(Default)]
pub struct Counters {
    pub seq1: u16,
    pub seq2: u16,
    pub seq3: u16,
    pub seq4: u16,
    pub prespidx: u8,
}

impl Counters {
    pub fn sequence1(&mut self) -> u16 {
        self.seq1 = if self.seq1 >= 4096 { 1 } else { self.seq1 + 1 };
        self.seq1
    }

    pub fn sequence2(&mut self) -> u16 {
        self.seq2 = if self.seq2 >= 4096 { 1 } else { self.seq2 + 1 };
        self.seq2
    }

    pub fn sequence3(&mut self) -> u16 {
        self.seq3 = if self.seq3 >= 4096 { 1 } else { self.seq3 + 1 };
        self.seq3
    }

    pub fn sequence4(&mut self) -> u16 {
        self.seq4 = if self.seq4 >= 4096 { 1 } else { self.seq4 + 1 };
        self.seq4
    }

    pub fn proberesponseindex(&mut self) -> u8 {
        self.prespidx = if self.prespidx >= 10 {
            0
        } else {
            self.prespidx + 1
        };
        self.prespidx
    }
}

pub struct WPOxideRuntime {
    rx_socket: OwnedFd,
    tx_socket: OwnedFd,
    ui_state: UiState,
    access_points: WiFiDeviceList<AccessPoint>,
    unassoc_clients: WiFiDeviceList<Station>,
    rogue_client: MacAddress,
    handshake_storage: HandshakeStorage,
    frame_count: u64,
    eapol_count: u64,
    error_count: u64,
    interface: ntlook::Interface,
    counters: Counters,
    status_log: status::MessageLog,
}

impl WPOxideRuntime {
    pub fn new(interface_name: String) -> Self {
        let access_points = WiFiDeviceList::new();
        let unassoc_clients = WiFiDeviceList::new();
        let handshake_storage = HandshakeStorage::new();
        let mut log = status::MessageLog::new(10000);
        let iface = match get_interface_info_name(&interface_name) {
            Ok(inf) => inf,
            Err(e) => {
                eprintln!("{}", e);
                exit(EXIT_FAILURE);
            }
        };

        let idx = iface.index.unwrap();

        log.add_message(StatusMessage::new(
            MessageType::Info,
            format!("Setting {} down.", interface_name),
        ));
        set_interface_down(idx).ok();

        let rogue_client = MacAddress::random();
        log.add_message(StatusMessage::new(
            MessageType::Info,
            format!("Randomizing {} mac to {}", interface_name, rogue_client),
        ));
        set_interface_mac(idx, &rogue_client.0).ok();

        log.add_message(StatusMessage::new(
            MessageType::Info,
            format!("Setting {} monitor mode.", interface_name),
        ));
        set_interface_monitor(idx).ok();

        log.add_message(StatusMessage::new(
            MessageType::Info,
            format!("Setting {} up.", interface_name),
        ));
        set_interface_up(idx).ok();

        let rx_socket = open_socket_rx(idx).expect("Failed to open RX Socket.");
        let tx_socket = open_socket_tx(idx).expect("Failed to open TX Socket.");

        log.add_message(StatusMessage::new(
            MessageType::Info,
            format!(
                "Sockets Opened Rx: {} Tx: {}",
                rx_socket.as_raw_fd(),
                tx_socket.as_raw_fd()
            ),
        ));
        let state = UiState {
            menu: 0,
            paused: false,
            ap_sort: 0,
            cl_sort: 0,
            hs_sort: 0,
            sort_reverse: false,
        };
        WPOxideRuntime {
            rx_socket,
            tx_socket,
            ui_state: state,
            frame_count: 0,
            eapol_count: 0,
            error_count: 0,
            handshake_storage,
            access_points,
            unassoc_clients,
            rogue_client,
            interface: iface,
            counters: Counters::default(),
            status_log: status::MessageLog::new(100),
        }
    }
}

fn handle_frame(oxide: &mut WPOxideRuntime, packet: &[u8]) -> Result<(), String> {
    let radiotap = match Radiotap::from_bytes(packet) {
        Ok(radiotap) => radiotap,
        Err(error) => {
            oxide.error_count += 1;
            oxide.status_log.add_message(StatusMessage::new(
                MessageType::Error,
                format!("Couldn't read packet data with Radiotap: {error:?}",),
            ));
            return Err(error.to_string());
        }
    };
    let current_channel = oxide.interface.frequency.clone().unwrap().channel.unwrap();
    let channel_u8: u8 = current_channel.get_channel_number();
    oxide.frame_count += 1;
    let payload = &packet[radiotap.header.length..];
    let fcs = if let Some(flags) = radiotap.flags {
        flags.fcs
    } else {
        false
    };
    match libwifi::parse_frame(payload, fcs) {
        Ok(frame) => match frame {
            Frame::Beacon(beacon_frame) => {
                let bssid = beacon_frame.header.address_3;

                let signal_strength = radiotap
                    .antenna_signal
                    .unwrap_or(AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?);
                if bssid.is_real_device() && !bssid.is_private() {
                    let station_info = &beacon_frame.station_info;
                    oxide.access_points.add_or_update_device(
                        bssid,
                        &AccessPoint::new(
                            bssid,
                            signal_strength,
                            station_info.ssid.clone(),
                            station_info.ds_parameter_set,
                            Some(APFlags {
                                apie_essid: station_info.ssid.as_ref().map(|_| true),
                                gs_ccmp: station_info
                                    .rsn_information
                                    .as_ref()
                                    .map(|rsn| rsn.group_cipher_suite == RsnCipherSuite::CCMP),
                                gs_tkip: station_info
                                    .rsn_information
                                    .as_ref()
                                    .map(|rsn| rsn.group_cipher_suite == RsnCipherSuite::TKIP),
                                cs_ccmp: station_info.rsn_information.as_ref().map(|rsn| {
                                    rsn.pairwise_cipher_suites.contains(&RsnCipherSuite::CCMP)
                                }),
                                cs_tkip: station_info.rsn_information.as_ref().map(|rsn| {
                                    rsn.pairwise_cipher_suites.contains(&RsnCipherSuite::TKIP)
                                }),
                                rsn_akm_psk: station_info
                                    .rsn_information
                                    .as_ref()
                                    .map(|rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSK)),
                                rsn_akm_psk256: station_info
                                    .rsn_information
                                    .as_ref()
                                    .map(|rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSK256)),
                                rsn_akm_pskft: station_info
                                    .rsn_information
                                    .as_ref()
                                    .map(|rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSKFT)),
                                wpa_akm_psk: station_info
                                    .wpa_info
                                    .as_ref()
                                    .map(|wpa| wpa.akm_suites.contains(&WpaAkmSuite::Psk)),
                                ap_mfp: station_info
                                    .rsn_information
                                    .as_ref()
                                    .map(|rsn| rsn.mfp_required),
                            }),
                            oxide.rogue_client,
                        ),
                    );
                };

                let _ = attack_beacon(oxide, &beacon_frame, &bssid);
            }
            Frame::ProbeRequest(probe_request_frame) => {
                let client_mac = probe_request_frame.header.address_2; // MAC address of the client
                let bssid = probe_request_frame.header.address_3; // MAC address of the AP (BSSID)
                let signal_strength = radiotap
                    .antenna_signal
                    .unwrap_or(AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?);
                let ssid = &probe_request_frame.station_info.ssid;

                if client_mac.is_real_device() && client_mac != oxide.rogue_client {
                    if !bssid.is_broadcast() {
                        // Directed probe request
                        match ssid {
                            Some(ssid) => {
                                // Add to unassoc clients.
                                oxide.unassoc_clients.add_or_update_device(
                                    client_mac,
                                    &Station::new_unassoc_station(
                                        client_mac,
                                        signal_strength,
                                        vec![],
                                    ),
                                );
                                // Attack it.
                                let _ = attack_probe_request_direct(
                                    oxide,
                                    &client_mac,
                                    &bssid,
                                    current_channel.get_channel_number(),
                                    ssid.to_string(),
                                );
                            }
                            None => {}
                        }
                    } else {
                        // undirected probe request

                        match ssid {
                            None => {
                                // Add to unassoc clients.
                                oxide.unassoc_clients.add_or_update_device(
                                    client_mac,
                                    &Station::new_unassoc_station(
                                        client_mac,
                                        signal_strength,
                                        vec![],
                                    ),
                                );
                                // Attack it.
                                let _ = attack_probe_request(
                                    oxide,
                                    &client_mac,
                                    current_channel.get_channel_number(),
                                    None,
                                );
                            }
                            Some(ssid) => {
                                // Add to unassoc clients.
                                oxide.unassoc_clients.add_or_update_device(
                                    client_mac,
                                    &Station::new_unassoc_station(
                                        client_mac,
                                        signal_strength,
                                        vec![ssid.to_string()],
                                    ),
                                );
                                // Attack it.
                                let _ = attack_probe_request(
                                    oxide,
                                    &client_mac,
                                    current_channel.get_channel_number(),
                                    Some(ssid.to_string()),
                                );
                            }
                        }
                    }
                }
            }
            Frame::ProbeResponse(probe_response_frame) => {
                // Assumption:
                //  Only an AP will send a probe response.
                //
                let bssid = &probe_response_frame.header.address_3;
                let signal_strength = radiotap
                    .antenna_signal
                    .unwrap_or(AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?);
                if bssid.is_real_device() {
                    let station_info = &probe_response_frame.station_info;
                    oxide.access_points.add_or_update_device(
                        *bssid,
                        &AccessPoint::new(
                            *bssid,
                            signal_strength,
                            probe_response_frame.station_info.ssid.clone(),
                            probe_response_frame.station_info.ds_parameter_set,
                            Some(APFlags {
                                apie_essid: station_info.ssid.as_ref().map(|_| true),
                                gs_ccmp: station_info
                                    .rsn_information
                                    .as_ref()
                                    .map(|rsn| rsn.group_cipher_suite == RsnCipherSuite::CCMP),
                                gs_tkip: station_info
                                    .rsn_information
                                    .as_ref()
                                    .map(|rsn| rsn.group_cipher_suite == RsnCipherSuite::TKIP),
                                cs_ccmp: station_info.rsn_information.as_ref().map(|rsn| {
                                    rsn.pairwise_cipher_suites.contains(&RsnCipherSuite::CCMP)
                                }),
                                cs_tkip: station_info.rsn_information.as_ref().map(|rsn| {
                                    rsn.pairwise_cipher_suites.contains(&RsnCipherSuite::TKIP)
                                }),
                                rsn_akm_psk: station_info
                                    .rsn_information
                                    .as_ref()
                                    .map(|rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSK)),
                                rsn_akm_psk256: station_info
                                    .rsn_information
                                    .as_ref()
                                    .map(|rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSK256)),
                                rsn_akm_pskft: station_info
                                    .rsn_information
                                    .as_ref()
                                    .map(|rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSKFT)),
                                wpa_akm_psk: station_info
                                    .wpa_info
                                    .as_ref()
                                    .map(|wpa| wpa.akm_suites.contains(&WpaAkmSuite::Psk)),
                                ap_mfp: station_info
                                    .rsn_information
                                    .as_ref()
                                    .map(|rsn| rsn.mfp_required),
                            }),
                            oxide.rogue_client,
                        ),
                    );
                    let _ = attack_probe_response(oxide, &probe_response_frame, bssid);
                };
            }
            Frame::Authentication(auth_frame) => {
                // Assumption:
                //  Authentication packets can be sent by the AP or Client.
                //  We will use the sequence number to decipher.

                let signal = radiotap
                    .antenna_signal
                    .unwrap_or(AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?);
                if auth_frame.auth_algorithm == 0 {
                    // Open system (Which can be open or WPA2)
                    if auth_frame.auth_seq == 1 {
                        //// From Client
                        let client = auth_frame.header.address_2;
                        let ap_addr = auth_frame.header.address_1;
                        let bssid = auth_frame.header.address_3;

                        // First let's add it to our unassociated clients list:
                        oxide.unassoc_clients.add_or_update_device(
                            client,
                            &Station::new_unassoc_station(client, signal, vec![]),
                        );

                        // Now let's... send an authentication response I guess.
                        let _ = attack_authentication_from_client(&client, &ap_addr, &bssid, oxide);
                    } else if auth_frame.auth_seq == 2 {
                        //// From AP
                        let client = auth_frame.header.address_1;
                        let ap_addr = auth_frame.header.address_2;

                        // Add AP
                        oxide.access_points.add_or_update_device(
                            ap_addr,
                            &AccessPoint::new(
                                ap_addr,
                                signal,
                                None,
                                Some(current_channel.get_channel_number()),
                                None,
                                oxide.rogue_client,
                            ),
                        );

                        if client != oxide.rogue_client {
                            // If it's not our rogue client that it's responding to.
                            oxide.unassoc_clients.add_or_update_device(
                                client,
                                &Station::new_unassoc_station(
                                    client,
                                    AntennaSignal::from_bytes(&[0u8])
                                        .map_err(|err| err.to_string())?,
                                    vec![],
                                ),
                            );
                        } else {
                            // Oh it is responding to us!
                            // Let's respond with an association request then
                            let _ = attack_authentication_from_ap(
                                &ap_addr,
                                &oxide.rogue_client.clone(),
                                oxide,
                            );
                        }
                    }
                }
            }
            Frame::Deauthentication(deauth_frame) => {
                // Assumption:
                //  Deauthentication packets can be sent by the AP or Client.
                //
                let from_ds: bool = deauth_frame.header.frame_control.from_ds();
                let to_ds: bool = deauth_frame.header.frame_control.to_ds();
                let ap_addr = if from_ds && !to_ds {
                    deauth_frame.header.address_2
                } else if !from_ds && to_ds {
                    deauth_frame.header.address_1
                } else {
                    // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                    // lets just ignore it lol
                    return Ok(());
                };

                let station_addr = if !from_ds && to_ds {
                    deauth_frame.header.address_2
                } else {
                    deauth_frame.header.address_1
                };

                let signal = radiotap
                    .antenna_signal
                    .unwrap_or(AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?);

                // Add AP
                if ap_addr.is_real_device() {
                    oxide.access_points.add_or_update_device(
                        ap_addr,
                        &AccessPoint::new(
                            ap_addr,
                            if from_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
                            },
                            None,
                            None,
                            None,
                            oxide.rogue_client,
                        ),
                    );
                }

                // If client sends deauth... we should probably treat as unassoc?
                if station_addr.is_real_device() && station_addr != oxide.rogue_client {
                    oxide.unassoc_clients.add_or_update_device(
                        station_addr,
                        &Station::new_unassoc_station(
                            station_addr,
                            if to_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
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
                    frame.header.address_2
                } else if !from_ds && to_ds {
                    frame.header.address_1
                } else {
                    // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                    // lets just ignore it lol
                    return Ok(());
                };

                let station_addr = if !from_ds && to_ds {
                    frame.header.address_2
                } else {
                    frame.header.address_1
                };

                let mut clients = WiFiDeviceList::<Station>::new(); // Clients list for AP.
                let signal = radiotap
                    .antenna_signal
                    .unwrap_or(AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?);

                if station_addr.is_real_device() && station_addr != oxide.rogue_client {
                    // Make sure this isn't a broadcast or rogue

                    let client = &Station::new_station(
                        station_addr,
                        if to_ds {
                            signal
                        } else {
                            AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
                        },
                        Some(ap_addr),
                    );
                    clients.add_or_update_device(station_addr, client);
                    oxide.unassoc_clients.remove_device(&station_addr);
                }
                let ap = AccessPoint::new_with_clients(
                    ap_addr,
                    if from_ds {
                        signal
                    } else {
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
                    },
                    None,
                    Some(channel_u8),
                    None,
                    clients,
                    oxide.rogue_client,
                );
                oxide.access_points.add_or_update_device(ap_addr, &ap);
            }
            Frame::AssociationRequest(assoc_request_frame) => {
                // Assumption:
                //  Only a client/potential client will ever submit an association request.
                //  This is how we will know to send a fake M1 and try to get an M2 from it.
                let client_mac = assoc_request_frame.header.address_2; // MAC address of the client
                let ap_mac = assoc_request_frame.header.address_1; // MAC address of the AP
                let bssid = assoc_request_frame.header.address_3; // MAC address of the AP (BSSID)

                // Handle client as not yet associated
                if client_mac.is_real_device() && client_mac != oxide.rogue_client {
                    oxide.unassoc_clients.add_or_update_device(
                        client_mac,
                        &Station::new_unassoc_station(
                            client_mac,
                            radiotap.antenna_signal.unwrap_or(
                                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                            ),
                            vec![],
                        ),
                    );
                };
                // Add AP
                if ap_mac.is_real_device() {
                    let ap = AccessPoint::new(
                        ap_mac,
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                        None,
                        Some(channel_u8),
                        None,
                        oxide.rogue_client,
                    );
                    oxide.access_points.add_or_update_device(ap_mac, &ap);
                };
                let _ = attack_association_request(
                    &client_mac,
                    &ap_mac,
                    &bssid,
                    &assoc_request_frame,
                    oxide,
                );
            }
            Frame::AssociationResponse(assoc_response_frame) => {
                // Assumption:
                //  Only a AP will ever submit an association response.
                //
                let client_mac = assoc_response_frame.header.address_1; // MAC address of the client
                let bssid = assoc_response_frame.header.address_2; // MAC address of the AP (BSSID)

                if bssid.is_real_device()
                    && client_mac.is_real_device()
                    && client_mac != oxide.rogue_client
                {
                    // Valid devices
                    let mut clients = WiFiDeviceList::<Station>::new();

                    if assoc_response_frame.status_code != 0 {
                        // Association was successful
                        let client = &Station::new_station(
                            client_mac,
                            AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                            Some(bssid),
                        );
                        clients.add_or_update_device(client_mac, client);
                        oxide.unassoc_clients.remove_device(&client_mac);
                    }
                    let station_info = &assoc_response_frame.station_info;
                    let ap = AccessPoint::new_with_clients(
                        bssid,
                        radiotap.antenna_signal.unwrap_or(
                            AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                        ),
                        None,
                        Some(channel_u8),
                        Some(APFlags {
                            apie_essid: station_info.ssid.as_ref().map(|_| true),
                            gs_ccmp: station_info
                                .rsn_information
                                .as_ref()
                                .map(|rsn| rsn.group_cipher_suite == RsnCipherSuite::CCMP),
                            gs_tkip: station_info
                                .rsn_information
                                .as_ref()
                                .map(|rsn| rsn.group_cipher_suite == RsnCipherSuite::TKIP),
                            cs_ccmp: station_info.rsn_information.as_ref().map(|rsn| {
                                rsn.pairwise_cipher_suites.contains(&RsnCipherSuite::CCMP)
                            }),
                            cs_tkip: station_info.rsn_information.as_ref().map(|rsn| {
                                rsn.pairwise_cipher_suites.contains(&RsnCipherSuite::TKIP)
                            }),
                            rsn_akm_psk: station_info
                                .rsn_information
                                .as_ref()
                                .map(|rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSK)),
                            rsn_akm_psk256: station_info
                                .rsn_information
                                .as_ref()
                                .map(|rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSK256)),
                            rsn_akm_pskft: station_info
                                .rsn_information
                                .as_ref()
                                .map(|rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSKFT)),
                            wpa_akm_psk: station_info
                                .wpa_info
                                .as_ref()
                                .map(|wpa| wpa.akm_suites.contains(&WpaAkmSuite::Psk)),
                            ap_mfp: station_info
                                .rsn_information
                                .as_ref()
                                .map(|rsn| rsn.mfp_required),
                        }),
                        clients,
                        oxide.rogue_client,
                    );
                    oxide.access_points.add_or_update_device(bssid, &ap);
                };
            }
            Frame::ReassociationRequest(frame) => {
                // Assumption:
                //  Only a client will ever submit an reassociation request.
                //  Attack includes sending a reassociation response and M1 frame- looks very similar to attacking an associataion request.
                let client_mac = frame.header.address_2; // MAC address of the client
                let new_ap = frame.header.address_1; // MAC address of the AP
                let old_ap = frame.current_ap_address;
                let ssid = frame.station_info.ssid;

                // Technically the client is still associated to the old AP. Let's add it there and we will handle moving it over if we get a reassociation response.
                if old_ap.is_real_device()
                    && client_mac.is_real_device()
                    && client_mac != oxide.rogue_client
                {
                    // Valid devices
                    let mut clients = WiFiDeviceList::<Station>::new();

                    // Setup client
                    let client = &Station::new_station(
                        client_mac,
                        radiotap.antenna_signal.unwrap_or(
                            AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                        ),
                        Some(old_ap),
                    );
                    clients.add_or_update_device(client_mac, client);
                    oxide.unassoc_clients.remove_device(&client_mac);

                    let ap = AccessPoint::new_with_clients(
                        old_ap,
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                        ssid.clone(),
                        None,
                        None,
                        clients,
                        oxide.rogue_client,
                    );
                    oxide.access_points.add_or_update_device(old_ap, &ap);

                    let newap = AccessPoint::new_with_clients(
                        new_ap,
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                        ssid.clone(),
                        Some(channel_u8),
                        None,
                        WiFiDeviceList::<Station>::new(),
                        oxide.rogue_client,
                    );
                    oxide.access_points.add_or_update_device(new_ap, &newap);
                };
            }
            Frame::ReassociationResponse(frame) => {
                // Assumption:
                //  Only a AP will ever submit a reassociation response.
                //
                let client_mac = frame.header.address_1; // MAC address of the client
                let ap_mac = frame.header.address_2; // MAC address of the AP (BSSID)

                if ap_mac.is_real_device()
                    && client_mac.is_real_device()
                    && client_mac != oxide.rogue_client
                {
                    // Valid devices
                    let mut clients = WiFiDeviceList::<Station>::new();

                    if frame.status_code != 0 {
                        // Association was successful
                        let client = &Station::new_station(
                            client_mac,
                            AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                            Some(ap_mac),
                        );
                        clients.add_or_update_device(client_mac, client);
                        oxide.unassoc_clients.remove_device(&client_mac);
                        // Find the old AP, remove this device from it.
                        if let Some(old_ap) = oxide.access_points.find_ap_by_client_mac(&client_mac)
                        {
                            old_ap.client_list.remove_device(&client_mac);
                        }
                    }
                    let ap = AccessPoint::new_with_clients(
                        ap_mac,
                        radiotap.antenna_signal.unwrap_or(
                            AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                        ),
                        None,
                        Some(channel_u8),
                        None,
                        clients,
                        oxide.rogue_client,
                    );
                    oxide.access_points.add_or_update_device(ap_mac, &ap);
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
                    source_mac
                } else if !from_ds && to_ds {
                    dest_mac
                } else {
                    // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                    // lets just ignore it lol
                    return Ok(());
                };
                let station_addr = if !from_ds && to_ds {
                    source_mac
                } else {
                    dest_mac
                };

                let mut clients = WiFiDeviceList::<Station>::new(); // Clients list for AP.
                let signal = radiotap
                    .antenna_signal
                    .unwrap_or(AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?);

                if station_addr.is_real_device() && station_addr != oxide.rogue_client {
                    // Make sure this isn't a broadcast or something

                    let client = &Station::new_station(
                        station_addr,
                        if to_ds {
                            signal
                        } else {
                            AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
                        },
                        Some(ap_addr),
                    );
                    clients.add_or_update_device(station_addr, client);
                    oxide.unassoc_clients.remove_device(&station_addr);
                }
                let ap = AccessPoint::new_with_clients(
                    ap_addr,
                    if from_ds {
                        signal
                    } else {
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
                    },
                    None,
                    Some(channel_u8),
                    None,
                    clients,
                    oxide.rogue_client,
                );
                oxide.access_points.add_or_update_device(ap_addr, &ap);
            }
            Frame::Cts(_) => {
                // Not really doing anything with these yet...
            }
            Frame::Ack(_) => {
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
                    source_mac
                } else if !from_ds && to_ds {
                    dest_mac
                } else {
                    // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                    // lets just ignore it lol
                    return Ok(());
                };
                let station_addr = if !from_ds && to_ds {
                    source_mac
                } else {
                    dest_mac
                };

                let mut clients = WiFiDeviceList::<Station>::new(); // Clients list for AP.
                let signal = radiotap
                    .antenna_signal
                    .unwrap_or(AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?);

                if station_addr.is_real_device() && station_addr != oxide.rogue_client {
                    // Make sure this isn't a broadcast or something

                    let client = &Station::new_station(
                        station_addr,
                        if to_ds {
                            signal
                        } else {
                            AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
                        },
                        Some(ap_addr),
                    );
                    clients.add_or_update_device(station_addr, client);
                    oxide.unassoc_clients.remove_device(&station_addr);
                }
                let ap = AccessPoint::new_with_clients(
                    ap_addr,
                    if from_ds {
                        signal
                    } else {
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
                    },
                    None,
                    Some(channel_u8),
                    None,
                    clients,
                    oxide.rogue_client,
                );
                oxide.access_points.add_or_update_device(ap_addr, &ap);
            }
            Frame::BlockAckRequest(frame) => {
                let source_mac = frame.source; // MAC address of the source
                let dest_mac = frame.destination; // MAC address of the destination
                let from_ds: bool = frame.frame_control.from_ds();
                let to_ds: bool = frame.frame_control.to_ds();

                // Figure out our AP and Client using from_ds / to_ds
                let ap_addr = if from_ds && !to_ds {
                    source_mac
                } else if !from_ds && to_ds {
                    dest_mac
                } else {
                    // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                    // lets just ignore it lol
                    return Ok(());
                };
                let station_addr = if !from_ds && to_ds {
                    source_mac
                } else {
                    dest_mac
                };

                let mut clients = WiFiDeviceList::<Station>::new(); // Clients list for AP.
                let signal = radiotap
                    .antenna_signal
                    .unwrap_or(AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?);

                if station_addr.is_real_device() && station_addr != oxide.rogue_client {
                    // Make sure this isn't a broadcast or something

                    let client = &Station::new_station(
                        station_addr,
                        if to_ds {
                            signal
                        } else {
                            AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
                        },
                        Some(ap_addr),
                    );
                    clients.add_or_update_device(station_addr, client);
                    oxide.unassoc_clients.remove_device(&station_addr);
                }
                let ap = AccessPoint::new_with_clients(
                    ap_addr,
                    if from_ds {
                        signal
                    } else {
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
                    },
                    None,
                    Some(channel_u8),
                    None,
                    clients,
                    oxide.rogue_client,
                );
                oxide.access_points.add_or_update_device(ap_addr, &ap);
            }
            Frame::Data(data_frame) => {
                handle_data_frame(&data_frame, &radiotap, oxide, channel_u8)?
            }
            Frame::NullData(data_frame) => {
                handle_null_data_frame(&data_frame, &radiotap, oxide, channel_u8)?
            }
            Frame::QosNull(data_frame) => {
                handle_null_data_frame(&data_frame, &radiotap, oxide, channel_u8)?
            }
            Frame::QosData(data_frame) => {
                handle_data_frame(&data_frame, &radiotap, oxide, channel_u8)?
            }
            Frame::DataCfAck(data_frame) => {
                handle_data_frame(&data_frame, &radiotap, oxide, channel_u8)?
            }
            Frame::DataCfPoll(data_frame) => {
                handle_data_frame(&data_frame, &radiotap, oxide, channel_u8)?
            }
            Frame::DataCfAckCfPoll(data_frame) => {
                handle_data_frame(&data_frame, &radiotap, oxide, channel_u8)?
            }
            Frame::CfAck(data_frame) => {
                handle_null_data_frame(&data_frame, &radiotap, oxide, channel_u8)?
            }
            Frame::CfPoll(data_frame) => {
                handle_null_data_frame(&data_frame, &radiotap, oxide, channel_u8)?
            }
            Frame::CfAckCfPoll(data_frame) => {
                handle_null_data_frame(&data_frame, &radiotap, oxide, channel_u8)?
            }
            Frame::QosDataCfAck(data_frame) => {
                handle_data_frame(&data_frame, &radiotap, oxide, channel_u8)?
            }
            Frame::QosDataCfPoll(data_frame) => {
                handle_data_frame(&data_frame, &radiotap, oxide, channel_u8)?
            }
            Frame::QosDataCfAckCfPoll(data_frame) => {
                handle_data_frame(&data_frame, &radiotap, oxide, channel_u8)?
            }
            Frame::QosCfPoll(data_frame) => {
                handle_null_data_frame(&data_frame, &radiotap, oxide, channel_u8)?
            }
            Frame::QosCfAckCfPoll(data_frame) => {
                handle_null_data_frame(&data_frame, &radiotap, oxide, channel_u8)?
            }
        },
        Err(err) => {
            if let libwifi::error::Error::Failure(message, _data) = err {
                match &message[..] {
                    "Input frame is too short to contain an FCS" => {}
                    "Frame Check Sequence (FCS) mismatch" => {}
                    "An error occured while parsing the data: nom::ErrorKind is Eof" => {}
                    _ => {
                        oxide.status_log.add_message(StatusMessage::new(
                            MessageType::Error,
                            format!("Libwifi Parsing Error: {message:?}",),
                        ));
                        oxide.error_count += 1;
                    }
                }
            }
        }
    };

    Ok(())
}

fn handle_data_frame(
    data_frame: &impl DataFrame,
    rthdr: &Radiotap,
    oxide: &mut WPOxideRuntime,
    chan: u8,
) -> Result<(), String> {
    let source = data_frame.header().src().expect("Unable to get src");
    let dest = data_frame.header().dest();
    let from_ds: bool = data_frame.header().frame_control.from_ds();
    let to_ds: bool = data_frame.header().frame_control.to_ds();
    let ap_addr = if from_ds && !to_ds {
        data_frame.header().address_2
    } else if !from_ds && to_ds {
        data_frame.header().address_1
    } else {
        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
        // lets just ignore it lol
        return Ok(());
    };

    let station_addr = if !from_ds && to_ds {
        data_frame.header().address_2
    } else {
        data_frame.header().address_1
    };

    let mut clients = WiFiDeviceList::<Station>::new(); // Clients list for AP.
    let signal = rthdr
        .antenna_signal
        .unwrap_or(AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?);

    if station_addr.is_real_device() && station_addr != oxide.rogue_client {
        // Make sure this isn't a broadcast or something

        let client = &Station::new_station(
            station_addr,
            if to_ds {
                signal
            } else {
                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
            },
            Some(ap_addr),
        );
        clients.add_or_update_device(station_addr, client);
        oxide.unassoc_clients.remove_device(&station_addr);
    }
    let ap = AccessPoint::new_with_clients(
        ap_addr,
        if from_ds {
            signal
        } else {
            AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
        },
        None,
        Some(chan),
        None,
        clients,
        oxide.rogue_client,
    );
    oxide.access_points.add_or_update_device(ap_addr, &ap);

    if let Some(eapol) = data_frame.eapol_key().clone() {
        oxide.eapol_count += 1;
        let essid: Option<String> = if let Some(ap) = oxide.access_points.get_device(&ap_addr) {
            ap.ssid.clone()
        } else {
            None
        };

        let result = oxide.handshake_storage.add_or_update_handshake(
            &ap_addr,
            &station_addr,
            eapol.clone(),
            essid,
        );
        match result {
            Ok(handshake) => {
                oxide.status_log.add_message(StatusMessage::new(
                    MessageType::Info,
                    format!(
                        "New Eapol: {source} => {dest} ({})",
                        eapol.determine_key_type()
                    ),
                ));
                if handshake.complete() {
                    if let Some(ap) = oxide.access_points.get_device(&ap_addr) {
                        ap.has_hs = true;
                    }
                }
                if handshake.has_pmkid() {
                    if let Some(ap) = oxide.access_points.get_device(&ap_addr) {
                        ap.has_pmkid = true;
                    }
                }
            }
            Err(e) => {
                oxide.status_log.add_message(StatusMessage::new(
                    MessageType::Info,
                    format!(
                        "Eapol Failed to Add: {source} => {dest} ({}) | {e}",
                        eapol.determine_key_type(),
                    ),
                ));
                /* oxide.status_log.add_message(StatusMessage::new(
                    MessageType::Info,
                    format!("Failed: {:?}", &eapol.to_bytes(),),
                )); */
            }
        }
    }
    Ok(())
}

fn handle_null_data_frame(
    data_frame: &impl NullDataFrame,
    rthdr: &Radiotap,
    oxide: &mut WPOxideRuntime,
    chan: u8,
) -> Result<(), String> {
    let from_ds: bool = data_frame.header().frame_control.from_ds();
    let to_ds: bool = data_frame.header().frame_control.to_ds();
    let ap_addr = if from_ds && !to_ds {
        data_frame.header().address_2
    } else if !from_ds && to_ds {
        data_frame.header().address_1
    } else {
        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
        // lets just ignore it lol
        return Ok(());
    };

    let station_addr = if !from_ds && to_ds {
        data_frame.header().address_2
    } else {
        data_frame.header().address_1
    };

    let mut clients = WiFiDeviceList::<Station>::new(); // Clients list for AP.
    let signal = rthdr
        .antenna_signal
        .unwrap_or(AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?);

    if station_addr.is_real_device() && station_addr != oxide.rogue_client {
        // Make sure this isn't a broadcast or something

        let client = &Station::new_station(
            station_addr,
            if to_ds {
                signal
            } else {
                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
            },
            Some(ap_addr),
        );
        clients.add_or_update_device(station_addr, client);
        oxide.unassoc_clients.remove_device(&station_addr);
    }
    let ap = AccessPoint::new_with_clients(
        ap_addr,
        if from_ds {
            signal
        } else {
            AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
        },
        None,
        Some(chan),
        None,
        clients,
        oxide.rogue_client,
    );
    oxide.access_points.add_or_update_device(ap_addr, &ap);
    Ok(())
}

fn write_packet(fd: i32, packet: &[u8]) -> Result<(), String> {
    let bytes_written =
        unsafe { libc::write(fd, packet.as_ptr() as *const libc::c_void, packet.len()) };

    if bytes_written < 0 {
        // An error occurred during write
        let error_code = io::Error::last_os_error();

        return Err(error_code.to_string());
    }

    Ok(())
}

fn read_packet(oxide: &mut WPOxideRuntime) -> Result<Vec<u8>, String> {
    let mut buffer = vec![0u8; 6000];
    let packet_len = unsafe {
        libc::read(
            oxide.rx_socket.as_raw_fd(),
            buffer.as_mut_ptr() as *mut libc::c_void,
            buffer.len(),
        )
    };

    // Handle non-blocking read
    if packet_len < 0 {
        let error_code = io::Error::last_os_error();
        if error_code.kind() == io::ErrorKind::WouldBlock {
            return Err("No data available".to_string());
        } else {
            // An actual error occurred
            oxide.error_count += 1;
            oxide.status_log.add_message(StatusMessage::new(
                MessageType::Error,
                format!("Error Reading from Socket: {error_code:?}"),
            ));
            return Err(error_code.to_string());
        }
    }

    buffer.truncate(packet_len as usize);
    Ok(buffer)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !geteuid().is_root() {
        println!("{}", get_art("You need to run as root!"));
        exit(EXIT_FAILURE);
    }

    let cli = Arguments::parse();

    let mut oxide = WPOxideRuntime::new(cli.interface);
    oxide.status_log.add_message(StatusMessage::new(
        MessageType::Info,
        "Starting...".to_string(),
    ));
    let iface = oxide.interface.clone();
    let idx = iface.index.unwrap();
    let interface_name =
        String::from_utf8(iface.name.unwrap()).expect("cannot get interface name from bytes.");

    let duration = Duration::from_secs(1);
    thread::sleep(duration);

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    let mut seconds_timer = Instant::now();
    let seconds_interval = Duration::from_secs(1);
    let mut frame_count_old = 0u64;
    let mut frame_rate = 0u64;

    let mut last_status_time = Instant::now();
    let status_interval = Duration::from_millis(100);

    let mut last_interactions_clear = Instant::now();
    let interactions_interval = Duration::from_secs(120);

    let hop_interval = Duration::from_secs(2);
    let mut last_hop_time = Instant::now();
    let channels = cli.channels;
    let mut cycle_iter = channels.iter().cycle();

    if let Some(&channel) = cycle_iter.next() {
        if let Err(e) = set_interface_chan(idx, channel) {
            eprintln!("{}", e);
        }
    }

    oxide.status_log.add_message(StatusMessage::new(
        MessageType::Info,
        format!("Setting channel hopper: {:?}", channels),
    ));

    //we don't really need this. We still process frames plenty fast and this had the potential of interupting us 
    //in the middle of trying to send out a response.
    //start_channel_hopping_thread(running.clone(), hop_interval, idx, channels);

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    let start_time = Instant::now();
    execute!(stdout(), Hide).unwrap();
    let _ = execute!(io::stdout(), EnterAlternateScreen)?;
    let cleanup = CleanUp;
    let _ = enable_raw_mode();
    while running.load(Ordering::SeqCst) {
        // Calculate last packet rate
        if seconds_timer.elapsed() >= seconds_interval {
            seconds_timer = Instant::now();

            // Calculate the frame rate
            let frames_processed = oxide.frame_count - frame_count_old;
            frame_count_old = oxide.frame_count;
            frame_rate = frames_processed;
        }

        if last_hop_time.elapsed() >= hop_interval {
            if let Some(&channel) = cycle_iter.next() {
                if let Err(e) = set_interface_chan(idx, channel) {
                    eprintln!("{}", e);
                }
                last_hop_time = Instant::now();
            }
        }

        // Start UI Messages
        if last_status_time.elapsed() >= status_interval {
            last_status_time = Instant::now();
            if poll(Duration::ZERO)? {
                let event = crossterm::event::read()?;
                if event == Event::Key(KeyCode::Right.into()) {
                    oxide.ui_state.menu_next();
                } else if event == Event::Key(KeyCode::Left.into()) {
                    oxide.ui_state.menu_back();
                } else if event == Event::Key(KeyCode::Char('q').into()) {
                    running.store(false, Ordering::SeqCst);
                } else if event == Event::Key(KeyCode::Char(' ').into()) {
                    oxide.ui_state.toggle_pause();
                } else if event == Event::Key(KeyCode::Char('a').into()) {
                    oxide.ui_state.ap_sort_next();
                } else if event == Event::Key(KeyCode::Char('c').into()) {
                    oxide.ui_state.cl_sort_next();
                } else if event == Event::Key(KeyCode::Char('r').into()) {
                    oxide.ui_state.toggle_reverse();
                }
            
            }
            print_ui(&mut oxide, start_time, frame_rate);
        }

        // Clear all interactions counters every 60 seconds.
        if last_interactions_clear.elapsed() >= interactions_interval {
            last_interactions_clear = Instant::now();
            oxide.access_points.clear_all_interactions();
        }

        // Read Packet
        if let Ok(packet) = read_packet(&mut oxide) {
            handle_frame(&mut oxide, &packet)?;
        }
    }

    oxide.status_log.add_message(StatusMessage::new(
        MessageType::Info,
        format!("Setting {} down.", interface_name),
    ));

    match set_interface_down(idx) {
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
    match set_interface_station(idx) {
        Ok(_) => {}
        Err(e) => {
            oxide.status_log.add_message(StatusMessage::new(
                MessageType::Error,
                format!("Error: {e:?}"),
            ));
        }
    }
    println!();
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

struct CleanUp;

impl Drop for CleanUp {
    fn drop(&mut self) {
        execute!(stdout(), Show).unwrap();
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen).expect("Could not leave alternate screen");
    }
    
}

#[allow(dead_code)]
fn start_channel_hopping_thread(
    running: Arc<AtomicBool>,
    hop_interval: Duration,
    idx: i32,
    channels: Vec<u8>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut cycle_iter = channels.iter().cycle();
        let mut last_hop_time = Instant::now();
        if let Some(&channel) = cycle_iter.next() {
            if let Err(e) = set_interface_chan(idx, channel) {
                eprintln!("{}", e);
            }
        }
        while running.load(Ordering::SeqCst) {
            if last_hop_time.elapsed() >= hop_interval {
                if let Some(&channel) = cycle_iter.next() {
                    if let Err(e) = set_interface_chan(idx, channel) {
                        eprintln!("{}", e);
                    }
                    last_hop_time = Instant::now();
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
    })
}
