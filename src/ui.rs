use std::{
    fmt::Write,
    io::stdout,
    process::exit,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crossterm::{
    cursor::MoveTo,
    execute,
    terminal::{self, ClearType},
};
use libc::EXIT_FAILURE;

use crate::{auth::FourWayHandshake, ntlook::get_interface_info_idx, WPOxideRuntime};

pub fn default_ui(oxide: &mut WPOxideRuntime, start_time: Instant, framerate: u64) {
    // Update interface
    match oxide.interface.index {
        Some(index) => match get_interface_info_idx(index) {
            Ok(infos) => oxide.interface = infos,
            Err(e) => {
                eprintln!("Failed to get interface info: {}", e);
                exit(EXIT_FAILURE);
            }
        },
        None => {
            eprintln!("Interface index is None");
            exit(EXIT_FAILURE);
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
        "{:^15} | {:^15} | {:^10} | {:^10} | {:^10}",
        format!(
            "Channel: {}",
            oxide
                .interface
                .frequency
                .as_ref()
                .unwrap()
                .channel
                .as_ref()
                .map_or("None".to_string(), |value| value.to_string())
        ),
        format!("Frames #: {}", oxide.frame_count),
        format!("Rate: {}/s", framerate),
        format!("Mac: {}", oxide.rogue_client),
        format!("Errors: {}", oxide.error_count),
    );
    writeln!(output, "{:<7} {:>7} | {:>80}", "WPOxide", time_str, status,).ok();
    writeln!(output, "{}", "-".repeat(101)).ok();

    /////////// Print Access Points ///////////

    let aps = format!("Access Points: {}", oxide.access_points.size());
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
        "MAC Address", "CH", "RSSI", "Last", "SSID", "Clients", "Int.", "4wHS", "PMKID",
    )
    .ok();

    let mut access_points: Vec<_> = oxide.access_points.get_devices().iter().collect();
    access_points.sort_by(|a, b| b.1.last_recv.cmp(&a.1.last_recv));

    let mut ap_len = 1;
    for (mac, ap_data) in access_points.clone() {
        if ap_len < 19 {
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
            let hss = oxide.handshake_storage.find_handshakes_by_ap(mac);
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
                ap_data.last_signal_strength.value.to_string(),
                epoch_to_string(ap_data.last_recv).to_string(),
                ssid,
                clients_size,
                ap_data.interactions,
                if pwnd_counter > 0 {
                    '\u{2705}'.to_string()
                } else {
                    " ".to_string()
                },
                if pmkid_counter > 0 {
                    '\u{2705}'.to_string()
                } else {
                    " ".to_string()
                },
            )
            .ok();
            ap_len += 1;
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

    let mut client_devices: Vec<_> = oxide.unassoc_clients.get_devices().iter().collect();
    let binding = oxide.access_points.get_all_clients();
    let new_clients: Vec<_> = binding.iter().collect();
    client_devices.extend(new_clients);

    let clnt = format!("Clients: {}", client_devices.len());
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

    client_devices.sort_by(|a, b| b.1.last_recv.cmp(&a.1.last_recv));
    let mut client_len = 0;
    for (mac, station_data) in client_devices.clone() {
        if client_len < 15 {
            let ap = if let Some(access_point) = station_data.access_point {
                access_point.to_string()
            } else {
                "".to_string()
            };
            writeln!(
                output,
                "{:<15} {:<15} {:<8} {:<18} {:<40}",
                mac.to_string(),
                ap,
                if station_data.last_signal_strength.value != 0 {
                    station_data.last_signal_strength.value.to_string()
                } else {
                    "".to_string()
                },
                epoch_to_string(station_data.last_recv),
                station_data.clone().probes_to_string_list(),
            )
            .ok();
            client_len += 1;
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

    let clnt = format!("Handshakes: {}", oxide.handshake_storage.count());
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
        "[M1 M2 M3 M4 MC] | [PM] | COMPLETE",
    ];
    writeln!(
        output,
        "{:<15} {:<15} {:<30} {:<30}",
        headers[0], headers[1], headers[2], headers[3],
    )
    .ok();

    let mut print_handshakes: Vec<&FourWayHandshake> = Vec::new();
    let mut hs_len = 0;
    let binding = oxide.handshake_storage.get_handshakes();
    for handshake_list in binding.values() {
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
            hs.mac_ap.unwrap().to_string(),
            hs.mac_client.unwrap().to_string(),
            hs.essid_to_string(),
            hs.to_string()
        )
        .ok();
        hs_len += 1;
        if hs_len >= 6 {
            if oxide.handshake_storage.count() > 6 {
                writeln!(
                    output,
                    "{:^100}",
                    format!(
                        "---- +{} more ----",
                        oxide.handshake_storage.count() - hs_len
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
    let mut recent_messages = oxide.status_log.get_recent_messages(15);
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
