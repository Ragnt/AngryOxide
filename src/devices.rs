use crate::ntlook::WiFiChannel;
use libwifi::frame::components::MacAddress;
use libwifi::frame::{EapolKey, MessageType};
use radiotap::field::{AntennaSignal, Field};
use rand::seq::IteratorRandom;
use rand::thread_rng;
use std::collections::HashMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
// Define a struct for general WiFi device properties
pub struct WiFiDevice {
    pub mac_address: MacAddress,             // MAC address of the device
    pub last_signal_strength: AntennaSignal, // Signal strength in dBm
    pub last_recv: u64,                      // Timestamp of the last received frame in epoch
    pub interactions: u64, // Number of times we have gone active against this device.
    pub device_type: WiFiDeviceType, // Device type with unique properties
}

// Enum for different WiFi device types
#[derive(Clone, Debug)]
pub enum WiFiDeviceType {
    AccessPoint(AccessPointData),
    Station(StationData),
}

// Struct to represent unique data for Access Points
#[derive(Clone, Debug, Default)]
pub struct AccessPointData {
    pub ssid: Option<String>,
    pub channel: Option<WiFiChannel>,
    pub client_list: WiFiDeviceList,
    pub information: AccessPointInformation,
    pub beacon_count: u32,
}

#[derive(Clone, Debug, Default)]
pub struct AccessPointInformation {
    pub apie_essid: Option<bool>,
    pub gs_ccmp: Option<bool>,
    pub gs_tkip: Option<bool>,
    pub cs_ccmp: Option<bool>,
    pub cs_tkip: Option<bool>,
    pub rsn_akm_psk: Option<bool>,
    pub rsn_akm_psk256: Option<bool>,
    pub rsn_akm_pskft: Option<bool>,
    pub wpa_akm_psk: Option<bool>,
    pub ap_mfp: Option<bool>,
}

impl AccessPointInformation {
    // Checks if the AKM is PSK from any one of the indicators
    pub fn akm_mask(&self) -> bool {
        self.rsn_akm_psk.unwrap_or(false)
            || self.rsn_akm_psk256.unwrap_or(false)
            || self.rsn_akm_pskft.unwrap_or(false)
            || self.wpa_akm_psk.unwrap_or(false)
    }

    // Function to update capabilities with non-None values from another instance
    pub fn update_with(&mut self, other: &AccessPointInformation) {
        if let Some(val) = other.apie_essid {
            self.apie_essid = Some(val);
        }
        if let Some(val) = other.gs_ccmp {
            self.gs_ccmp = Some(val);
        }
        if let Some(val) = other.gs_tkip {
            self.gs_tkip = Some(val);
        }
        if let Some(val) = other.cs_ccmp {
            self.cs_ccmp = Some(val);
        }
        if let Some(val) = other.cs_tkip {
            self.cs_tkip = Some(val);
        }
        if let Some(val) = other.rsn_akm_psk {
            self.rsn_akm_psk = Some(val);
        }
        if let Some(val) = other.rsn_akm_psk256 {
            self.rsn_akm_psk256 = Some(val);
        }
        if let Some(val) = other.rsn_akm_pskft {
            self.rsn_akm_pskft = Some(val);
        }
        if let Some(val) = other.wpa_akm_psk {
            self.wpa_akm_psk = Some(val);
        }
        if let Some(val) = other.ap_mfp {
            self.ap_mfp = Some(val);
        }
    }
}

#[derive(Clone, Debug)]
pub struct StationData {
    pub access_point: Option<MacAddress>,
    pub aid: Option<u16>,
    pub probes: Option<Vec<String>>, // directed probes by device
}

impl StationData {
    pub fn probes_to_string_list(&mut self) -> String {
        self.probes
            .as_ref()
            .unwrap_or(&Vec::new())
            .iter()
            .map(|ssid| ssid.to_string())
            .collect::<Vec<String>>()
            .join(", ")
    }
}

impl WiFiDevice {
    // Constructor for Access Point
    pub fn new_access_point(
        mac_address: MacAddress,
        signal_strength: AntennaSignal,
        ssid: Option<String>,
        channel: Option<u8>,
        information: Option<AccessPointInformation>,
    ) -> WiFiDevice {
        let client_list = WiFiDeviceList::new();
        let current_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let chan = if let Some(channel) = channel {
            WiFiChannel::new(channel)
        } else {
            None
        };

        WiFiDevice {
            mac_address,
            last_signal_strength: signal_strength,
            last_recv: current_epoch,
            interactions: 0,
            device_type: WiFiDeviceType::AccessPoint(AccessPointData {
                ssid,
                client_list,
                channel: chan,
                beacon_count: 0,
                information: if let Some(info) = information {
                    info
                } else {
                    AccessPointInformation::default()
                },
            }),
        }
    }

    pub fn new_access_point_with_client(
        mac_address: MacAddress,
        signal_strength: AntennaSignal,
        ssid: Option<String>,
        clients: Vec<WiFiDevice>,
        channel: Option<u8>,
        information: Option<AccessPointInformation>,
    ) -> WiFiDevice {
        let mut client_list = WiFiDeviceList::new();
        for cl in clients {
            client_list.add_device(cl);
        }
        let current_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        let chan = if let Some(channel) = channel {
            WiFiChannel::new(channel)
        } else {
            None
        };

        WiFiDevice {
            mac_address,
            last_signal_strength: signal_strength,
            last_recv: current_epoch,
            interactions: 0,
            device_type: WiFiDeviceType::AccessPoint(AccessPointData {
                ssid,
                client_list,
                channel: chan,
                beacon_count: 0,
                information: if let Some(info) = information {
                    info
                } else {
                    AccessPointInformation::default()
                },
            }),
        }
    }

    // Constructor for Station
    pub fn new_station(
        mac_address: MacAddress,
        signal_strength: AntennaSignal,
        aid: Option<u16>,
        access_point: Option<MacAddress>,
    ) -> WiFiDevice {
        let current_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        WiFiDevice {
            mac_address,
            last_signal_strength: signal_strength,
            last_recv: current_epoch,
            interactions: 0,
            device_type: WiFiDeviceType::Station(StationData {
                access_point,
                aid,
                probes: None,
            }),
        }
    }

    pub fn new_unassoc_station(
        mac_address: MacAddress,
        signal_strength: AntennaSignal,
        probes: Vec<String>,
    ) -> WiFiDevice {
        let current_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        WiFiDevice {
            mac_address,
            last_signal_strength: signal_strength,
            last_recv: current_epoch,
            interactions: 0,
            device_type: WiFiDeviceType::Station(StationData {
                access_point: None,
                aid: None,
                probes: Some(probes),
            }),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct WiFiDeviceList {
    devices: HashMap<MacAddress, WiFiDevice>,
}

impl WiFiDeviceList {
    // Create a new WiFiDeviceList
    pub fn new() -> WiFiDeviceList {
        WiFiDeviceList {
            devices: HashMap::new(),
        }
    }

    pub fn size(&mut self) -> usize {
        self.devices.len()
    }

    pub fn get_random(&self) -> Option<&WiFiDevice> {
        let mut rng = thread_rng();
        self.devices.values().choose(&mut rng)
    }

    // Function to combine client lists from all access points into a single Vec
    pub fn get_all_clients(&self) -> HashMap<MacAddress, WiFiDevice> {
        self.devices
            .values()
            .filter_map(|device| match &device.device_type {
                WiFiDeviceType::AccessPoint(ap_data) => Some(&ap_data.client_list.devices),
                _ => None,
            })
            .flat_map(|map| map.iter())
            .map(|(mac, device)| (mac.clone(), device.clone()))
            .collect()
    }

    pub fn find_ap_by_client_mac(&self, client_mac: &MacAddress) -> Option<&WiFiDevice> {
        self.devices
            .values()
            .find(|device| matches!(&device.device_type, WiFiDeviceType::AccessPoint(ap_data) if ap_data.client_list.devices.contains_key(client_mac)))
    }

    pub fn clear_all_interactions(&mut self) {
        for dev in self.devices.values_mut() {
            dev.interactions = 0;
        }
    }

    // Retrieve a device by MAC address
    pub fn add_or_update_device(&mut self, mac_address: MacAddress, new_device: WiFiDevice) {
        if let Some(device) = self.devices.get_mut(&mac_address) {
            device.last_recv = new_device.last_recv;
            if new_device.last_signal_strength != AntennaSignal::from_bytes(&[0u8]).unwrap() {
                // we dont want to update the signal strength if it wasn't from this device.
                device.last_signal_strength = new_device.last_signal_strength;
            }
            match &mut device.device_type {
                WiFiDeviceType::AccessPoint(apdata) => {
                    match new_device.device_type {
                        WiFiDeviceType::AccessPoint(newdata) => {
                            // Iterate clients and add or update those to match our new list.
                            for (mac, client) in newdata.client_list.devices {
                                apdata.client_list.add_or_update_device(mac, client);
                            }

                            // update ssid if its empty (even if the new one is empty, why not)
                            if apdata.ssid.is_none() {
                                apdata.ssid = newdata.ssid;
                            }

                            // update information field with new info
                            apdata.information.update_with(&newdata.information);
                        }
                        WiFiDeviceType::Station(_) => {
                            panic!("Trying to replace a AP with a Station.")
                        }
                    }
                }
                WiFiDeviceType::Station(stationdata) => {
                    let probes: &mut Vec<String> =
                        &mut stationdata.probes.clone().unwrap_or(vec![]);
                    match new_device.device_type {
                        WiFiDeviceType::Station(newdata) => {
                            for new_probe in newdata.probes.unwrap_or(vec![]) {
                                if !probes.contains(&new_probe) {
                                    probes.push(new_probe);
                                }
                            }
                        }
                        WiFiDeviceType::AccessPoint(_) => {
                            panic!("Trying to replace a Station with an AP.")
                        }
                    }
                }
            }
        } else {
            self.devices
                .insert(new_device.mac_address.clone(), new_device);
        }
    }

    // Add a new device to the list
    pub fn remove_device(&mut self, mac: &MacAddress) {
        self.devices.remove(mac);
    }

    // Add a new device to the list
    pub fn add_device(&mut self, device: WiFiDevice) {
        self.devices.insert(device.mac_address.clone(), device);
    }

    // Retrieve a device by MAC address
    pub fn get_device(&mut self, mac_address: &MacAddress) -> Option<&mut WiFiDevice> {
        self.devices.get_mut(mac_address)
    }

    // Retrieve all devices
    pub fn get_devices(&mut self) -> &mut HashMap<MacAddress, WiFiDevice> {
        &mut self.devices
    }
}

// PMKID struct definition
#[derive(Debug, Clone, Copy)]
pub struct Pmkid {
    pub id: u8,
    pub len: u8,
    pub oui: [u8; 3],
    pub t: u8,
    pub pmkid: [u8; 16],
}

// PMKID struct conversion implementation
impl Pmkid {
    fn from_bytes(bytes: &[u8]) -> Self {
        // Ensure the slice has the correct length
        if bytes.len() != 22 {
            panic!("Invalid PMKID data length");
        }
        let mut pmkid = Pmkid {
            id: bytes[0],
            len: bytes[1],
            oui: [bytes[2], bytes[3], bytes[4]],
            t: bytes[5],
            pmkid: [0; 16],
        };
        pmkid.pmkid.copy_from_slice(&bytes[6..]);
        pmkid
    }
}

/*
// Example usage
let mut handshake = FourWayHandshake::new();
handshake.add_key(eapol_key_msg1)?;
handshake.add_key(eapol_key_msg2)?;
// ... and so on for msg3 and msg4 */
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

// Example implementation for displaying a FourWayHandshake
impl fmt::Display for FourWayHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Example handshake detail (customize as needed)

        write!(
            f,
            " {:^2} {:^2} {:^2} {:^2} {:^3}  {:^8}   {:^5}",
            if self.msg1.is_some() { "xx" } else { " " },
            if self.msg2.is_some() { "xx" } else { " " },
            if self.msg3.is_some() { "xx" } else { " " },
            if self.msg4.is_some() { "xx" } else { " " },
            if self.mic.is_some() { "xxx" } else { " " },
            if self.complete() { '\u{2714}' } else { ' ' },
            if self.has_pmkid() { "xxxxx" } else { "     " }
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
        self.eapol_client.is_some()
            && self.mic.is_some()
            && self.anonce.is_some()
            && self.snonce.is_some()
            && self.mac_ap.is_some()
            && self.mac_client.is_some()
            && self.essid.is_some()
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

    pub fn add_key(&mut self, new_key: EapolKey) -> Result<(), &'static str> {
        let key_type = new_key.clone().determine_key_type();
        // Define the RSN Suite OUI for PMKID validation
        let rsnsuiteoui: [u8; 3] = [0x00, 0x0f, 0xac];

        if key_type == MessageType::Message1 && self.msg1.is_none() {
            // Validate Message 1: should have no MIC, contains ANonce
            if new_key.key_mic != [0u8; 16] {
                return Err("Invalid Message 1: MIC should not be present");
            }

            if new_key.key_data_length as usize > 0 {
                println!(
                    "KEY!!!! {} | {:02x?}",
                    &new_key.key_data_length, new_key.key_data
                )
            }

            // Check for PMKID presence and validity
            if new_key.key_data_length as usize == 16 {
                // Extract PMKID from the key data
                let pmkid_data = &new_key.key_data[0..16];
                let pmkid = Pmkid::from_bytes(pmkid_data);

                if pmkid.oui == rsnsuiteoui
                    && pmkid.len >= 0x14
                    && pmkid.t == 4
                    && pmkid.pmkid.iter().any(|&x| x != 0)
                {
                    self.pmkid = Some(pmkid)
                }
            }

            self.anonce = Some(new_key.key_nonce);
            self.msg1 = Some(new_key.clone());
            self.last_msg = Some(new_key.clone());
        } else if key_type == MessageType::Message2 && self.msg2.is_none() {
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
                && new_key.replay_counter <= self.msg1.clone().unwrap().replay_counter
                && new_key.replay_counter > self.msg1.clone().unwrap().replay_counter + 3
            {
                return Err("Invalid Message 2: RC value not within range.");
            }

            //Temporal Checking
            if self.msg1.clone().is_some_and(|msg1| {
                new_key
                    .timestamp
                    .duration_since(msg1.timestamp)
                    .unwrap()
                    .as_secs()
                    > 2
            }) {
                return Err("Invalid Message 2: Time difference too great.");
            }

            self.snonce = Some(new_key.key_nonce);
            self.msg2 = Some(new_key.clone());
            self.last_msg = Some(new_key.clone());
            self.eapol_client = Some(new_key.to_bytes().unwrap());
            self.mic = Some(new_key.key_mic);
            // This is good news, we have collected a M2 which gives us a solid MIC, EapolClient, and SNONCE.
        } else if key_type == MessageType::Message3 && self.msg3.is_none() {
            // Validate Message 3: should have MIC, contains ANonce, GTK
            if new_key.key_mic == [0u8; 16] {
                return Err("Invalid Message 3: MIC should be present");
            }
            if new_key.key_nonce == [0u8; 32] {
                return Err("Invalid Message 3: Anonce should be present.");
            }

            // Nonce-correction logic
            self.nc = if let Some(anonce) = self.anonce {
                if new_key.key_nonce[..28] == anonce[..28] {
                    // Compare first 28 bytes
                    if new_key.key_nonce[28..] != anonce[28..] {
                        // Compare last 4 bytes
                        if anonce[31] != new_key.key_nonce[31] {
                            // Compare Byte 31 for LE
                            self.l_endian = true;
                        } else if anonce[28] != new_key.key_nonce[28] {
                            // Compare Byte 28 for BE
                            self.b_endian = true;
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

            if self.msg2.is_some()
                && new_key.replay_counter <= self.msg2.clone().unwrap().replay_counter
                && new_key.replay_counter > self.msg2.clone().unwrap().replay_counter + 3
            {
                return Err("Invalid Message 3: RC value not within range.");
            }

            //Temporal Checking
            if self.msg2.clone().is_some_and(|msg2| {
                new_key
                    .timestamp
                    .duration_since(msg2.timestamp)
                    .unwrap()
                    .as_secs()
                    > 2
            }) {
                return Err("Invalid Message 3: Time difference too great.");
            }

            self.msg3 = Some(new_key.clone());
            self.last_msg = Some(new_key.clone());
            // Message 3 cannot be used for the EAPOL_CLIENT because it is sent by the AP.
        } else if key_type == MessageType::Message4 && self.msg4.is_none() {
            // Validate Message 4: should have MIC
            if new_key.key_mic == [0u8; 16] {
                return Err("Invalid Message 4: MIC should be present");
            }
            if self.msg3.is_some()
                && new_key.replay_counter <= self.msg3.clone().unwrap().replay_counter
                && new_key.replay_counter > self.msg3.clone().unwrap().replay_counter + 3
            {
                return Err("Invalid Message 4: RC value not within range.");
            }

            //Temporal Checking
            if self.msg3.clone().is_some_and(|msg3| {
                new_key
                    .timestamp
                    .duration_since(msg3.timestamp)
                    .unwrap()
                    .as_secs()
                    > 2
            }) {
                return Err("Invalid Message 4: Time difference too great.");
            }

            self.msg4 = Some(new_key.clone());
            self.last_msg = Some(new_key.clone());
            // If we dont have an snonce, theres a chance our M4 isn't zeroed and therefore we can use the snonce from it.
            if self.snonce.is_none() && new_key.key_nonce != [0u8; 32] {
                self.snonce = Some(new_key.key_nonce);

                // If we don't have a message 2, we will use the M4 as our EAPOL_CLIENT (only if it's non-zeroed).
                if self.eapol_client.is_none() {
                    self.mic = Some(new_key.key_mic);
                    self.eapol_client = Some(new_key.to_bytes().unwrap())
                }
            }
        } else {
            return Err("Handshake already complete or message already present.");
        }

        Ok(())
    }

    pub fn to_hashcat_22000_format(&self) -> Option<String> {
        if !self.complete() {
            return None;
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

        // For essid_hex
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

        // Calculate the message pair value
        let message_pair = self.calculate_message_pair();

        Some(format!(
            "WPA*02*{}*{}*{}*{}*{}*{}*{}",
            mic_hex,
            mac_ap_hex,
            mac_client_hex,
            essid_hex,
            anonce_hex,
            eapol_client_hex,
            message_pair
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
        } else if self.msg1.is_some() && self.msg2.is_some() {
            message_pair |= 0x00; // M1+M2, EAPOL from M2 (challenge)
        } else if self.msg1.is_some() && self.msg4.is_some() {
            message_pair |= 0x01; // M1+M4, EAPOL from M4
        } else if self.msg3.is_some() && self.msg4.is_some() {
            message_pair |= 0x05; // M3+M4, EAPOL from M4
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
pub struct HandshakeStorage {
    handshakes: HashMap<HandshakeSessionKey, Vec<FourWayHandshake>>,
}

impl HandshakeStorage {
    pub fn new() -> Self {
        HandshakeStorage {
            handshakes: HashMap::new(),
        }
    }

    // Updated count function
    pub fn count(&self) -> usize {
        self.handshakes.values().map(|v| v.len()).sum()
    }

    // This function remains the same as it already returns a HashMap with a Vec of handshakes
    pub fn get_handshakes(&self) -> HashMap<HandshakeSessionKey, Vec<FourWayHandshake>> {
        self.handshakes.clone()
    }

    // Updated find_handshakes_by_ap function
    pub fn find_handshakes_by_ap(
        &self,
        ap_mac: &MacAddress,
    ) -> HashMap<MacAddress, Vec<FourWayHandshake>> {
        self.handshakes
            .iter()
            .filter(|(key, _)| &key.ap_mac == ap_mac)
            .map(|(key, handshakes)| (key.client_mac.clone(), handshakes.clone()))
            .collect()
    }

    // Updated has_complete_handshake_for_ap function
    pub fn has_complete_handshake_for_ap(&self, ap_mac: &MacAddress) -> bool {
        self.handshakes.iter().any(|(key, handshakes)| {
            &key.ap_mac == ap_mac && handshakes.iter().any(|hs| hs.complete())
        })
    }

    pub fn add_or_update_handshake(
        &mut self,
        ap_mac: &MacAddress,
        client_mac: &MacAddress,
        new_key: EapolKey,
        essid: Option<String>,
    ) -> Result<(), &'static str> {
        let session_key = HandshakeSessionKey::new(ap_mac.clone(), client_mac.clone());

        let handshake_list = self.handshakes.entry(session_key).or_default();
        for handshake in &mut *handshake_list {
            if handshake.add_key(new_key.clone()).is_ok() {
                handshake.mac_ap = Some(ap_mac.clone());
                handshake.mac_client = Some(client_mac.clone());
                handshake.essid = essid;
                return Ok(());
            }
        }
        let mut new_handshake = FourWayHandshake::new(); // Create a new FourWayHandshake instance
        new_handshake.add_key(new_key)?;
        new_handshake.mac_ap = Some(ap_mac.clone());
        new_handshake.mac_client = Some(client_mac.clone());
        new_handshake.essid = essid;
        handshake_list.push(new_handshake);
        Ok(())
    }
}
