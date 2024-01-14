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
