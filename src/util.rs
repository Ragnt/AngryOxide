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
