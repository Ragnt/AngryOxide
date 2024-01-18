use std::{
    collections::HashMap,
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use chrono::{DateTime, Local};

use libwifi::frame::{components::MacAddress, EapolKey, MessageType, Pmkid};

use crate::{util::epoch_to_string, OxideRuntime};

#[derive(Clone, Debug, Default)]
pub struct FourWayHandshake {
    pub msg1: Option<EapolKey>,
    pub msg2: Option<EapolKey>,
    pub msg3: Option<EapolKey>,
    pub msg4: Option<EapolKey>,
    pub last_msg: Option<EapolKey>,
    pub eapol_client: Option<Vec<u8>>,
    pub mic: Option<[u8; 16]>,
    pub anonce: Option<[u8; 32]>,
    pub snonce: Option<[u8; 32]>,
    pub apless: bool,
    pub nc: bool,
    pub l_endian: bool,
    pub b_endian: bool,
    pub pmkid: Option<Pmkid>,
    pub mac_ap: Option<MacAddress>,
    pub mac_client: Option<MacAddress>,
    pub essid: Option<String>,
}

impl fmt::Display for FourWayHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {

        write!(
            f,
            " {:<2} {:<2} {:<2} {:<2}     {:^2}    {:^8}",
            if self.msg1.is_some() {
                "\u{2705}"
            } else {
                "--"
            },
            if self.msg2.is_some() {
                "\u{2705}"
            } else {
                "--"
            },
            if self.msg3.is_some() {
                "\u{2705}"
            } else {
                "--"
            },
            if self.msg4.is_some() {
                "\u{2705}"
            } else {
                "--"
            },
            if self.has_pmkid() { "\u{2705}\0" } else { "--" },
            if self.complete() { "\u{2705}\0" } else { "--" },
        )
    }
}

impl FourWayHandshake {
    pub fn new() -> Self {
        FourWayHandshake {
            msg1: None,
            msg2: None,
            msg3: None,
            msg4: None,
            last_msg: None,
            eapol_client: None,
            mic: None,
            anonce: None,
            snonce: None,
            apless: false,
            nc: false,
            l_endian: false,
            b_endian: false,
            pmkid: None,
            mac_ap: None,
            mac_client: None,
            essid: None,
        }
    }

    pub fn complete(&self) -> bool {
        (self.eapol_client.is_some()
            && self.mic.is_some()
            && self.anonce.is_some()
            && self.snonce.is_some()
            && self.mac_ap.is_some()
            && self.mac_client.is_some()
            && self.essid.is_some())
            || self.has_pmkid()
    }

    pub fn has_m1(&self) -> bool {
        self.msg1.is_some()
    }

    pub fn has_pmkid(&self) -> bool {
        self.pmkid.is_some()
    }

    pub fn essid_to_string(&self) -> String {
        if let Some(essid) = self.essid.clone() {
            essid
        } else {
            "".to_string()
        }
    }

    pub fn data_to_string(&self) -> (String, String, String, String, String, String, String) {
        let mut tuple = (
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
        );

        tuple.0 = if self.msg1.is_some() {
            "\u{2705}".to_string()
        } else {
            "--".to_string()
        };

        tuple.1 = if self.msg2.is_some() {
            "\u{2705}".to_string()
        } else {
            "--".to_string()
        };

        tuple.2 = if self.msg3.is_some() {
            "\u{2705}".to_string()
        } else {
            "--".to_string()
        };

        tuple.3 = if self.msg4.is_some() {
            "\u{2705}".to_string()
        } else {
            "--".to_string()
        };

        tuple.4 = if self.has_pmkid() {
            "\u{2705}".to_string()
        } else {
            "--".to_string()
        };

        tuple.5 = if self.complete() {
            "\u{2705}".to_string()
        } else {
            "--".to_string()
        };

        tuple.6 = if self.nc {
            if self.l_endian {
                "LE".to_string()
            } else if self.b_endian {
                "BE".to_string()
            } else {
                "\u{2705}".to_string()
            }
        } else {
            if self.apless {
                "RG".to_string()
            } else {
                "--".to_string()
            }
        };
        tuple
    }

    pub fn get_eapol_keys(&self) -> Vec<(u8, EapolKey)> {
        let mut keys: Vec<(u8, EapolKey)> = Vec::new();

        if let Some(ref key) = self.msg1 {
            keys.push((1, key.clone()));
        }
        if let Some(ref key) = self.msg2 {
            keys.push((2, key.clone()));
        }
        if let Some(ref key) = self.msg3 {
            keys.push((3, key.clone()));
        }
        if let Some(ref key) = self.msg4 {
            keys.push((4, key.clone()));
        }

        keys
    }

    pub fn add_key(&mut self, new_key: &EapolKey) -> Result<(), &'static str> {
        let key_type = new_key.determine_key_type();

        if key_type == MessageType::GTK {
            return Err("EAPOL is a GTK Update... ignoring.");
        }

        // Let's only accept MSG1 in order
        if key_type == MessageType::Message1 && self.msg1.is_none() {
            // Validate Message 1: should have no MIC, contains ANonce
            if new_key.key_mic != [0u8; 16] {
                return Err("Invalid Message 1: MIC should not be present");
            }

            // Compare RC to MSG 1
            if self.msg2.is_some()
                && new_key.replay_counter > self.msg2.clone().unwrap().replay_counter
            {
                return Err("Invalid Message 1: RC value not within range.");
            }

            //Temporal Checking
            if self.last_msg.clone().is_some_and(|msg| {
                new_key
                    .timestamp
                    .duration_since(msg.timestamp)
                    .unwrap_or(Duration::from_secs(1))
                    .as_millis()
                    > 200
            }) {
                return Err("Invalid Message 1: Time difference too great.");
            }

            // Check ANonce against M3 if M3 already present
            if self.msg3.is_some()
                && new_key.key_nonce[..28] != self.msg3.clone().unwrap().key_nonce[..28]
            {
                return Err("Invalid Message 1: M1 came after M3 with incorrect ANonce");
            }

            // Check for PMKID
            if let Ok(pmkid) = new_key.has_pmkid() {
                self.pmkid = Some(pmkid)
            };
            // Only update the anonce if there isn't one, because if we have one we have a msg3 already.
            if self.anonce.is_none() {
                self.anonce = Some(new_key.key_nonce);
            }
            self.msg1 = Some(new_key.clone());
            self.last_msg = Some(new_key.clone());
        } else if key_type == MessageType::Message2 {
            // Validate Message 2: should have MIC
            if new_key.key_mic == [0u8; 16] {
                return Err("Invalid Message 2: MIC should be present");
            }

            // Should have Snonce
            if new_key.key_nonce == [0u8; 32] {
                return Err("Invalid Message 2: Snonce should be present.");
            }

            // Compare RC to MSG 1
            if self.msg1.is_some()
                && (new_key.replay_counter < self.msg1.clone().unwrap().replay_counter
                    || new_key.replay_counter
                        > self.msg1.clone().unwrap().replay_counter.saturating_add(3))
            {
                return Err("Invalid Message 2: RC value not within range.");
            }

            //Temporal Checking
            if self.last_msg.clone().is_some_and(|msg| {
                new_key
                    .timestamp
                    .duration_since(msg.timestamp)
                    .unwrap()
                    .as_millis()
                    > 200
            }) {
                return Err("Invalid Message 2: Time difference too great.");
            }

            if self.msg1.is_some()
                && new_key.replay_counter > self.msg1.clone().unwrap().replay_counter
            {
                // Mark for Nonce Correction
                self.nc = true;
            }

            self.snonce = Some(new_key.key_nonce);
            self.msg2 = Some(new_key.clone());
            self.last_msg = Some(new_key.clone());
            let mut key_zeroed = new_key.clone();
            key_zeroed.key_mic = [0u8; 16];
            self.eapol_client = Some(key_zeroed.to_bytes().unwrap());
            self.mic = Some(new_key.key_mic);
            // This is good news, we have collected a M2 which gives us a solid MIC, EapolClient, and SNONCE.
        } else if key_type == MessageType::Message3 {
            // Validate Message 3: should have MIC, contains ANonce, GTK
            if new_key.key_mic == [0u8; 16] {
                return Err("Invalid Message 3: MIC should be present");
            }

            if new_key.key_nonce == [0u8; 32] {
                return Err("Invalid Message 3: Anonce should be present.");
            }

            if self.msg2.is_some()
                && new_key.replay_counter < self.msg2.clone().unwrap().replay_counter
                && new_key.replay_counter > self.msg2.clone().unwrap().replay_counter + 3
            {
                return Err("Invalid Message 3: RC value not within range.");
            }

            //Temporal Checking
            if self.last_msg.clone().is_some_and(|msg| {
                new_key
                    .timestamp
                    .duration_since(msg.timestamp)
                    .unwrap()
                    .as_millis()
                    > 200
            }) {
                return Err("Invalid Message 3: Time difference too great.");
            }

            // Nonce-correction logic
            self.nc = if let Some(anonce) = self.anonce {
                if new_key.key_nonce[..28] == anonce[..28] {
                    // Compare first 28 bytes
                    if new_key.key_nonce[28..] != anonce[28..] {
                        // Compare last 4 bytes
                        if anonce[28] != new_key.key_nonce[28] {
                            // Compare Byte 28 for BE
                            self.b_endian = true;
                        } else {
                            self.l_endian = true;
                        }
                        true // 0-28 are same, last 4 are different.
                    } else {
                        false // 0-28 and last four are same- no NC needed
                    }
                } else {
                    // 0-28 aren't even close, let's ditch this key.
                    return Err("Invalid Message 3: Anonce not close enough to Message 1 Anonce.");
                }
            } else {
                // We don't have an M1 to compare to, so assume it's good... and need to set the anonce.
                self.anonce = Some(new_key.key_nonce);
                false
            };

            self.msg3 = Some(new_key.clone());
            self.last_msg = Some(new_key.clone());
        } else if key_type == MessageType::Message4 {
            // Validate Message 4: should have MIC
            if new_key.key_mic == [0u8; 16] {
                return Err("Invalid Message 4: MIC should be present");
            }

            // Validate Replay Counter
            if (self.msg3.is_some()
                && (new_key.replay_counter < self.msg3.clone().unwrap().replay_counter
                    || new_key.replay_counter > (self.msg3.clone().unwrap().replay_counter + 3)))
                || (self.msg2.is_some()
                    && (new_key.replay_counter < self.msg2.clone().unwrap().replay_counter
                        || new_key.replay_counter
                            > (self.msg2.clone().unwrap().replay_counter + 3)))
            {
                return Err("Invalid Message 4: RC value not within range.");
            }

            //Temporal Checking
            if self.last_msg.clone().is_some_and(|msg: EapolKey| {
                new_key
                    .timestamp
                    .duration_since(msg.timestamp)
                    .unwrap()
                    .as_millis()
                    > 200
            }) {
                return Err("Invalid Message 4: Time difference too great.");
            }

            self.msg4 = Some(new_key.clone());
            self.last_msg = Some(new_key.clone());

            // If we dont have an snonce, theres a chance our M4 isn't zeroed and therefore we can use the snonce from it.
            if self.snonce.is_none() && new_key.key_nonce != [0u8; 32] {
                self.snonce = Some(new_key.key_nonce);

                // If we don't have a message 2, we will use the M4 as our EAPOL_CLIENT (only if it's non-zeroed).
                if self.eapol_client.is_none() && new_key.key_mic != [0u8; 16] {
                    self.mic = Some(new_key.key_mic);
                    let mut key_zeroed = new_key.clone();
                    key_zeroed.key_mic = [0u8; 16];
                    self.eapol_client = Some(key_zeroed.to_bytes().unwrap());
                }
            }
        } else {
            return Err(
                "Handshake already complete, message already present, or EAPOL out of order.",
            );
        }
        Ok(())
    }

    pub fn to_hashcat_22000_format(&self) -> Option<String> {
        let mut output = String::new();

        if let Some(pmkid) = &self.pmkid {
            if let Some(pmkid_format) = self.generate_pmkid_hashcat_format(pmkid) {
                output += &pmkid_format;
                output += "\n";
            }
        }

        if !self.complete() && output.is_empty() {
            return None;
        } else if !self.complete() && !output.is_empty() {
            return Some(output);
        }

        let mic_hex = self
            .mic
            .as_ref()?
            .iter()
            .fold(String::new(), |mut acc, &byte| {
                acc.push_str(&format!("{:02x}", byte));
                acc
            });

        let mac_ap_hex = self.mac_ap.as_ref()?.to_string();
        let mac_client_hex = self.mac_client.as_ref()?.to_string();

        let essid_hex =
            self.essid
                .as_ref()?
                .as_bytes()
                .iter()
                .fold(String::new(), |mut acc, &byte| {
                    acc.push_str(&format!("{:02x}", byte));
                    acc
                });

        let anonce_hex = self
            .anonce
            .as_ref()?
            .iter()
            .fold(String::new(), |mut acc, &byte| {
                acc.push_str(&format!("{:02x}", byte));
                acc
            });

        let eapol_client_hex =
            self.eapol_client
                .as_ref()?
                .iter()
                .fold(String::new(), |mut acc, &byte| {
                    acc.push_str(&format!("{:02x}", byte));
                    acc
                });

        let message_pair = self.calculate_message_pair();

        output += &format!(
            "WPA*02*{}*{}*{}*{}*{}*{}*{}",
            mic_hex,
            mac_ap_hex,
            mac_client_hex,
            essid_hex,
            anonce_hex,
            eapol_client_hex,
            message_pair
        );

        Some(output)
    }

    fn generate_pmkid_hashcat_format(&self, pmkid: &Pmkid) -> Option<String> {
        let pmkid_hex = pmkid.pmkid.iter().fold(String::new(), |mut acc, &byte| {
            acc.push_str(&format!("{:02x}", byte));
            acc
        });

        let mac_ap_hex = self.mac_ap.as_ref()?.to_string();
        let mac_client_hex = self.mac_client.as_ref()?.to_string();
        let essid_hex =
            self.essid
                .as_ref()?
                .as_bytes()
                .iter()
                .fold(String::new(), |mut acc, &byte| {
                    acc.push_str(&format!("{:02x}", byte));
                    acc
                });

        // hard coding the messagepair field to 02 for
        Some(format!(
            "WPA*01*{}*{}*{}*{}***02",
            pmkid_hex, mac_ap_hex, mac_client_hex, essid_hex
        ))
    }

    fn calculate_message_pair(&self) -> String {
        let mut message_pair = 0;

        if self.apless {
            message_pair |= 0x10; // Set the AP-less bit
        }
        if self.nc {
            message_pair |= 0x80; // Set the Nonce-Correction bit
        }
        if self.l_endian {
            message_pair |= 0x20; // Set the Little Endian bit
        }
        if self.b_endian {
            message_pair |= 0x40; // Set the Big Endian bit
        }

        // Determine the basic message pair based on messages present
        if self.msg2.is_some() && self.msg3.is_some() {
            message_pair |= 0x02; // M2+M3, EAPOL from M2
            return format!("{:02x}", message_pair);
        } else if self.msg1.is_some() && self.msg2.is_some() {
            message_pair |= 0x00; // M1+M2, EAPOL from M2 (challenge)
            return format!("{:02x}", message_pair);
        } else if self.msg1.is_some() && self.msg4.is_some() {
            message_pair |= 0x01; // M1+M4, EAPOL from M4
            return format!("{:02x}", message_pair);
        } else if self.msg3.is_some() && self.msg4.is_some() {
            message_pair |= 0x05; // M3+M4, EAPOL from M4
            return format!("{:02x}", message_pair);
        }

        format!("{:02x}", message_pair)
    }
}

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct HandshakeSessionKey {
    pub ap_mac: MacAddress,
    pub client_mac: MacAddress,
}

impl HandshakeSessionKey {
    fn new(ap_mac: MacAddress, client_mac: MacAddress) -> Self {
        HandshakeSessionKey { ap_mac, client_mac }
    }
}

// Stores collected 4-way-handshakes
#[derive(Debug, Clone)]
pub struct HandshakeStorage {
    handshakes: HashMap<HandshakeSessionKey, Vec<FourWayHandshake>>,
}

impl HandshakeStorage {
    pub fn new() -> Self {
        HandshakeStorage {
            handshakes: HashMap::new(),
        }
    }

    pub fn count(&self) -> usize {
        self.handshakes.values().map(|v| v.len()).sum()
    }

    pub fn get_handshakes(&self) -> HashMap<HandshakeSessionKey, Vec<FourWayHandshake>> {
        self.handshakes.clone()
    }

    pub fn has_complete_handshake_for_ap(&self, ap_mac: &MacAddress) -> bool {
        self.handshakes.iter().any(|(key, handshakes)| {
            &key.ap_mac == ap_mac && handshakes.iter().any(|hs| hs.complete())
        })
    }

    pub fn has_m1_for_ap(&self, ap_mac: &MacAddress) -> bool {
        self.handshakes.iter().any(|(key, handshakes)| {
            &key.ap_mac == ap_mac && handshakes.iter().any(|hs| hs.has_m1())
        })
    }

    pub fn add_or_update_handshake(
        &mut self,
        ap_mac: &MacAddress,
        client_mac: &MacAddress,
        new_key: EapolKey,
        essid: Option<String>,
    ) -> Result<&mut FourWayHandshake, &'static str> {
        let session_key = HandshakeSessionKey::new(*ap_mac, *client_mac);

        let handshake_list = self.handshakes.entry(session_key).or_default();

        // Sort the handshake list so that the most recent handshake is first.
        handshake_list.sort_by(|a, b| {
            b.last_msg
                .as_ref()
                .map_or(std::time::SystemTime::UNIX_EPOCH, |x| x.timestamp)
                .cmp(
                    &a.last_msg
                        .as_ref()
                        .map_or(std::time::SystemTime::UNIX_EPOCH, |x| x.timestamp),
                )
        });

        let mut index_to_return: Option<usize> = None;

        for (index, handshake) in handshake_list.iter_mut().enumerate() {
            if handshake.add_key(&new_key).is_ok() {
                handshake.mac_ap = Some(*ap_mac);
                handshake.mac_client = Some(*client_mac);
                handshake.essid = essid.clone();
                index_to_return = Some(index);
                break;
            }
        }

        if let Some(index) = index_to_return {
            return Ok(&mut handshake_list[index]);
        }

        // If we don't find a suitable handshake, create a new one and add it.
        let mut new_handshake = FourWayHandshake::new();
        new_handshake.add_key(&new_key)?;
        new_handshake.mac_ap = Some(*ap_mac);
        new_handshake.mac_client = Some(*client_mac);
        new_handshake.essid = essid;

        handshake_list.push(new_handshake);
        Ok(handshake_list.last_mut().unwrap())
    }

    pub fn get_table(
        &mut self,
        selected_row: Option<usize>,
    ) -> (Vec<String>, Vec<(Vec<String>, u16)>) {
        // Header fields
        let headers = vec![
            "Timestamp".to_string(),
            "AP MAC".to_string(),
            "Client MAC".to_string(),
            "SSID".to_string(),
            "M1".to_string(),
            "M2".to_string(),
            "M3".to_string(),
            "M4".to_string(),
            "PM".to_string(),
            "OK".to_string(),
            "NC".to_string(),
        ];

        // Make our handshakes list
        let mut print_handshakes: Vec<&FourWayHandshake> = Vec::new();

        let binding = self.get_handshakes();
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

        let mut rows: Vec<(Vec<String>, u16)> = Vec::new();

        for (idx, handshake) in print_handshakes.iter().enumerate() {
            let mut height = 1;

            let datetime: DateTime<Local> = handshake.last_msg.clone().unwrap().timestamp.into();
            let timestamp_str = datetime.format("%H:%M:%S").to_string();

            let mut hs_row = vec![
                format!("{}", timestamp_str),                             // Timestamp 0
                format!("{}", handshake.mac_ap.unwrap().to_string()),     // MAC Address 1
                format!("{}", handshake.mac_client.unwrap().to_string()), // Client Mac 2
                format!("{}", handshake.essid_to_string()),               // SSID 3
                format!("{}", handshake.data_to_string().0),              // M1
                format!("{}", handshake.data_to_string().1),              // M2
                format!("{}", handshake.data_to_string().2),              // M3
                format!("{}", handshake.data_to_string().3),              // M4
                format!("{}", handshake.data_to_string().4),              // PM
                format!("{}", handshake.data_to_string().5),              // OK
                format!("{}", handshake.data_to_string().6),              // NC
            ];

            if selected_row.is_some() && idx == selected_row.unwrap() {
                let mut keys = handshake.get_eapol_keys();
                if !keys.is_empty() {
                    // add header row
                    let merged = add_handshake_header_row(hs_row);
                    hs_row = merged;
                    height += 1;

                    keys.sort_by(|a, b| b.1.timestamp.cmp(&a.1.timestamp));
                    keys.reverse();
                    let start_time = keys[0].1.timestamp;

                    for (idx, (_keynum, key)) in keys.iter().enumerate() {
                        let last = idx == keys.len() - 1;
                        let merged = add_handshake_message_row(hs_row, key, last, start_time);
                        hs_row = merged;
                        height += 1;
                    }
                }
            }
            rows.push((hs_row, height));
        }
        (headers, rows)
    }
}

fn add_handshake_header_row(hs_row: Vec<String>) -> Vec<String> {
    let min_length = hs_row.len();

    let icon = "└ ";
    let mut merged = Vec::with_capacity(min_length);

    // Timestamp
    let new_str: String = format!("{}\n {}{}", hs_row[0], icon, "Relative");
    merged.push(new_str);

    // AP Mac
    let new_str: String = format!("{}\n {}{}", hs_row[1], icon, "MIC");
    merged.push(new_str);

    // Client MAC
    let new_str: String = format!("{}\n {}{}", hs_row[2], icon, "ReplayCounter");
    merged.push(new_str);

    // SSID
    let new_str: String = format!("{}\n {}{}", hs_row[3], icon, "NOnce");
    merged.push(new_str);

    // M1
    let new_str: String = format!("{}\n", hs_row[4]);
    merged.push(new_str);

    // M2
    let new_str: String = format!("{}\n", hs_row[5]);
    merged.push(new_str);

    // M3
    let new_str: String = format!("{}\n", hs_row[6]);
    merged.push(new_str);

    // M4
    let new_str: String = format!("{}\n", hs_row[7]);
    merged.push(new_str);

    // PM
    let new_str: String = format!("{}\n", hs_row[8]);
    merged.push(new_str);

    // OK
    let new_str: String = format!("{}\n", hs_row[9]);
    merged.push(new_str);

    // NC
    let new_str: String = format!("{}\n", hs_row[10]);
    merged.push(new_str);

    merged
}

fn add_handshake_message_row(
    hs_row: Vec<String>,
    message: &EapolKey,
    last: bool,
    start_time: SystemTime,
) -> Vec<String> {
    let min_length = hs_row.len();
    let icon = if last { "└ " } else { "├ " };
    let check = "\u{2714}".to_string();
    let mut merged = Vec::with_capacity(min_length);

    // Format the relative time to a decimal.
    let relative_time = message
        .timestamp
        .duration_since(start_time)
        .unwrap_or(Duration::from_secs(0));

    let total_milliseconds =
        (relative_time.as_secs() * 1000) as f64 + relative_time.subsec_millis() as f64;

    let formatted_time = format!("{:.0}ms", total_milliseconds);

    // Key Mic
    let key_mic_hex: String = message
        .key_mic
        .iter()
        .fold(String::new(), |mut acc, &byte| {
            acc.push_str(&format!("{:02x}", byte));
            acc
        });

    // AP MAC 0
    let new_str: String = format!("{}\n  {}{}", hs_row[0], icon, formatted_time);
    merged.push(new_str);

    // Client MAC 1
    let new_str: String = format!("{}\n  {}{}", hs_row[1], icon, key_mic_hex);
    merged.push(new_str);

    // SSID 2
    let new_str: String = format!("{}\n  {}{}", hs_row[2], icon, message.replay_counter);
    merged.push(new_str);

    let last_4_hex: String = message.key_nonce[28..]
        .iter()
        .fold(String::new(), |acc, &byte| acc + &format!("{:02x}", byte));

    let new_str: String = format!("{}\n  {}..{}", hs_row[3], icon, last_4_hex);
    merged.push(new_str);

    // M1
    if message.determine_key_type() == MessageType::Message1 {
        let new_str: String = format!("{}\n{}", hs_row[4], check);
        merged.push(new_str);
    } else {
        let new_str: String = format!("{}\n--", hs_row[4]);
        merged.push(new_str);
    }

    // M2
    if message.determine_key_type() == MessageType::Message2 {
        let new_str: String = format!("{}\n{}", hs_row[5], check);
        merged.push(new_str);
    } else {
        let new_str: String = format!("{}\n--", hs_row[5]);
        merged.push(new_str);
    }

    // M3
    if message.determine_key_type() == MessageType::Message3 {
        let new_str: String = format!("{}\n{}", hs_row[6], check);
        merged.push(new_str);
    } else {
        let new_str: String = format!("{}\n--", hs_row[6]);
        merged.push(new_str);
    }

    // M4
    if message.determine_key_type() == MessageType::Message4 {
        let new_str: String = format!("{}\n{}", hs_row[7], check);
        merged.push(new_str);
    } else {
        let new_str: String = format!("{}\n--", hs_row[7]);
        merged.push(new_str);
    }

    // PM
    if message.has_pmkid().is_ok() {
        let new_str: String = format!("{}\n{}", hs_row[8], check);
        merged.push(new_str);
    } else {
        let new_str: String = format!("{}\n--", hs_row[8]);
        merged.push(new_str);
    }

    // OK
    let new_str: String = format!("{}\n--", hs_row[9]);
    merged.push(new_str);

    // NC
    let new_str: String = format!("{}\n--", hs_row[10]);
    merged.push(new_str);

    merged
}
