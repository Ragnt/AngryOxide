use chrono::{DateTime, Utc};
use libwifi::frame::components::WpsInformation;
use libwifi::frame::{EapolKey, KeyInformation};
use radiotap::field::ext::TimeUnit;
use std::fs::File;
use std::io;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn epoch_to_string(epoch: u64) -> String {
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

pub fn slice_to_hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn epoch_to_iso_string(epoch: u64) -> String {
    match UNIX_EPOCH.checked_add(Duration::from_secs(epoch)) {
        Some(epoch_time) => DateTime::<Utc>::from(epoch_time).format("%+").to_string(),
        None => "Invalid timestamp".to_string(),
    }
}

pub fn system_time_to_iso8601(system_time: SystemTime) -> String {
    let datetime: DateTime<Utc> = system_time.into();
    datetime.to_rfc3339()
}

pub fn key_info_to_json_str(keyinfo: KeyInformation) -> String {
    format!(
        "{{\"descriptor_version\": {},\"key_type\": {},\"key_index\": {},\"install\": {},\"key_ack\": {},\"key_mic\": {},\"secure\": {},\"error\": {},\"request\": {},\"encrypted_key_data\": {},\"smk_message\": {}}}",
        keyinfo.descriptor_version,
        keyinfo.key_type,
        keyinfo.key_index,
        keyinfo.install,
        keyinfo.key_ack,
        keyinfo.key_mic,
        keyinfo.secure,
        keyinfo.error,
        keyinfo.request,
        keyinfo.encrypted_key_data,
        keyinfo.smk_message
    )
}

pub fn eapol_to_json_str(key: &EapolKey) -> String {
    format!("{{\"protocol_version\": {},\"timestamp\": \"{}\",\"key_information\": {},\"key_length\": {},\"replay_counter\": {},\"key_nonce\": \"{}\",\"key_iv\": \"{}\",\"key_rsc\": {},\"key_id\": {},\"key_mic\": \"{}\",\"key_data\": \"{}\"}}",
    key.protocol_version,
    system_time_to_iso8601(key.timestamp),
    key_info_to_json_str(key.parse_key_information()),
    key.key_length,
    key.replay_counter,
    slice_to_hex_string(&key.key_nonce),
    slice_to_hex_string(&key.key_iv),
    key.key_rsc,
    &key.key_id,
    slice_to_hex_string(&key.key_mic),
    slice_to_hex_string(&key.key_data))
}

pub fn option_bool_to_json_string(option: Option<bool>) -> String {
    match option {
        Some(true) => "true".to_string(),
        Some(false) => "false".to_string(),
        None => "\"none\"".to_string(),
    }
}

pub fn merge_with_newline(vec1: Vec<String>, vec2: Vec<String>) -> Vec<String> {
    let min_length = std::cmp::min(vec1.len(), vec2.len());

    // Iterate up to the shortest length, merging corresponding elements with a newline
    let mut merged = Vec::with_capacity(min_length);
    for i in 0..min_length {
        let new_str = format!("{}\n{}", vec1[i], vec2[i]);
        merged.push(new_str);
    }

    merged
}

pub fn ts_to_system_time(timestamp: u64, unit: TimeUnit) -> SystemTime {
    match unit {
        TimeUnit::Milliseconds => UNIX_EPOCH + Duration::from_millis(timestamp),
        TimeUnit::Microseconds => UNIX_EPOCH + Duration::from_micros(timestamp),
        TimeUnit::Nanoseconds => UNIX_EPOCH + Duration::from_nanos(timestamp),
    }
}

pub fn parse_ip_address_port(input: &str) -> Result<(IpAddr, u16), &'static str> {
    let parts: Vec<&str> = input.split(':').collect();

    // Check if there are exactly two parts
    if parts.len() != 2 {
        return Err("Input should be in the format IP_ADDRESS:PORT");
    }

    // Parse IP address
    let ip = match IpAddr::from_str(parts[0]) {
        Ok(ip) => ip,
        Err(_) => return Err("Invalid IP address"),
    };

    // Parse port
    let port = match parts[1].parse::<u16>() {
        Ok(port) => port,
        Err(_) => return Err("Invalid port number"),
    };

    Ok((ip, port))
}

pub fn is_file_less_than_100mb(file: &File) -> io::Result<bool> {
    let metadata = file.metadata()?;
    Ok(metadata.len() < 100 * 1024 * 1024)
}

pub fn max_column_widths(headers: &[String], rows: &[(Vec<String>, u16)]) -> Vec<usize> {
    let mut max_widths = headers.iter().map(|h| h.len()).collect::<Vec<_>>();

    for (row_data, _) in rows {
        for (i, cell) in row_data.iter().enumerate() {
            let adjusted_length = cell
                .chars()
                .fold(0, |acc, ch| acc + if ch == '✅' { 2 } else { 1 });
            max_widths[i] = max_widths[i].max(adjusted_length);
        }
    }

    max_widths
}

pub fn format_row(row: &[String], widths: &[usize]) -> String {
    row.iter()
        .enumerate()
        .map(|(i, cell)| {
            // Count the number of special characters
            let special_chars_count = cell.chars().filter(|&ch| ch == '✅').count();
            // Adjust width by reducing 1 space for each special character
            let adjusted_width = if special_chars_count > 0 {
                widths[i].saturating_sub(special_chars_count)
            } else {
                widths[i]
            };
            format!("{:width$}", cell, width = adjusted_width)
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

pub fn wps_to_json(wps_info: &Option<WpsInformation>) -> String {
    if let Some(wps) = wps_info {
        format!("{{\"setup_state\": \"{:?}\", \"manufacturer\": \"{}\", \"model\": \"{}\", \"model_number\": \"{}\", \"serial_number\": \"{}\", \"primary_device_type\": \"{}\", \"device_name\": \"{}\"}}",
    wps.setup_state,
    wps.manufacturer,
    wps.model,
    wps.model_number,
    wps.serial_number,
    wps.primary_device_type,
    wps.device_name)
    } else {
        "{}".to_string()
    }
}
