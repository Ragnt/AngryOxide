use globset::Glob;
use libwifi::frame::components::{MacAddress, WpsInformation};
use nl80211_ng::channels::{WiFiBand, WiFiChannel};
use radiotap::field::{AntennaSignal, Field};
use rand::seq::IteratorRandom;
use rand::thread_rng;
use std::collections::HashMap;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::oui::OuiRecord;
use crate::util::{epoch_to_iso_string, epoch_to_string, option_bool_to_json_string, wps_to_json};

// Constants for timeouts
const CONST_T1_TIMEOUT: Duration = Duration::from_secs(5); // Do not change state unless five seconds has passed.
const CONST_T2_TIMEOUT: Duration = Duration::from_millis(200); // Still need a purpose for this.

//////////////////////////////////////////////////////////////////////
#[derive(Clone, Debug)]
pub struct AuthSequence {
    pub t1: SystemTime,
    pub t2: SystemTime,
    pub rogue_mac: MacAddress,
    pub state: u8,
}

impl AuthSequence {
    fn new(rogue_mac: MacAddress) -> Self {
        AuthSequence {
            t1: SystemTime::UNIX_EPOCH,
            t2: SystemTime::now(),
            rogue_mac: MacAddress::random_with_oui(&rogue_mac),
            state: 0,
        }
    }

    // Checks if CONST_T1_TIMEOUT has elapsed since t1
    // Timer 1 is an interaction timer - elapsed means we have passed 1 second
    pub fn is_t1_timeout(&self) -> bool {
        self.t1
            .elapsed()
            .map_or(false, |elapsed| elapsed > CONST_T1_TIMEOUT)
    }

    // Checks if CONST_T2_TIMEOUT has elapsed since t2
    // Timer 2 is a timer of WHEN state last changed.
    pub fn is_t2_timeout(&self) -> bool {
        self.t2
            .elapsed()
            .map_or(false, |elapsed| elapsed > CONST_T2_TIMEOUT)
    }

    // Reset t1
    pub fn reset_t1(&mut self) -> SystemTime {
        self.t1 = SystemTime::now();
        self.t1
    }

    // Reset t2
    pub fn reset_t2(&mut self) -> SystemTime {
        self.t2 = SystemTime::now();
        self.t2
    }

    // Resets state to 0
    pub fn reset_state(&mut self) {
        self.state = 0;
    }

    // Increments state
    pub fn increment_state(&mut self) {
        self.state = self.state.saturating_add(1);
    }
}

// Trait to restrict WiFiDeviceList
pub trait WiFiDeviceType {}

trait HasSSID {
    fn ssid(&self) -> &Option<String>;
}

#[derive(Clone, Debug)]
pub struct AccessPoint {
    pub mac_address: MacAddress,
    pub oui_data: Option<OuiRecord>,
    pub last_signal_strength: AntennaSignal,
    pub last_recv: u64,
    pub interactions: u64,
    pub ssid: Option<String>,
    pub channel: Option<WiFiChannel>,
    pub client_list: WiFiDeviceList<Station>,
    pub information: APFlags,
    pub beacon_count: u32,
    pub auth_sequence: AuthSequence,
    pub has_hs: bool,
    pub has_pmkid: bool,
    pub is_target: bool,
    pub is_whitelisted: bool,
    pub wps_data: Option<WpsInformation>
}

impl WiFiDeviceType for AccessPoint {}

impl HasSSID for AccessPoint {
    fn ssid(&self) -> &Option<String> {
        &self.ssid
    }
}

impl Default for AccessPoint {
    fn default() -> Self {
        AccessPoint {
            mac_address: MacAddress([255, 255, 255, 255, 255, 255]),
            oui_data: None,
            last_signal_strength: AntennaSignal::from_bytes(&[0u8]).unwrap(),
            last_recv: 0,
            interactions: 0,
            ssid: None,
            channel: None,
            client_list: WiFiDeviceList::default(),
            information: APFlags::default(),
            beacon_count: 0,
            auth_sequence: AuthSequence::new(MacAddress([255, 255, 255, 255, 255, 255])),
            has_hs: false,
            has_pmkid: false,
            is_target: false,
            is_whitelisted: false,
            wps_data: None
        }
    }
}

impl AccessPoint {
    pub fn new(
        mac_address: MacAddress,
        last_signal_strength: AntennaSignal,
        ssid: Option<String>,
        channel: Option<(WiFiBand, u8)>,
        information: Option<APFlags>,
        rogue_mac: MacAddress,
        wps_data: Option<WpsInformation>,
        oui_data: Option<OuiRecord>
    ) -> Self {
        let client_list = WiFiDeviceList::new();
        let last_recv = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let chan = if let Some(channel) = channel {
            WiFiChannel::new(channel.1, channel.0)
        } else {
            None
        };

        AccessPoint {
            mac_address,
            oui_data,
            last_signal_strength,
            last_recv,
            interactions: 0,
            ssid,
            client_list,
            channel: chan,
            beacon_count: 0,
            information: if let Some(info) = information {
                info
            } else {
                APFlags::default()
            },
            auth_sequence: AuthSequence::new(rogue_mac),
            has_hs: false,
            has_pmkid: false,
            is_target: false,
            is_whitelisted: false,
            wps_data
        }
    }

    pub fn new_with_clients(
        mac_address: MacAddress,
        last_signal_strength: AntennaSignal,
        ssid: Option<String>,
        channel: Option<(WiFiBand, u8)>,
        information: Option<APFlags>,
        client_list: WiFiDeviceList<Station>,
        rogue_mac: MacAddress,
        wps_data: Option<WpsInformation>,
        oui_data: Option<OuiRecord>,
    ) -> Self {
        let last_recv = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let chan = if let Some(channel) = channel {
            WiFiChannel::new(channel.1, channel.0)
        } else {
            None
        };

        AccessPoint {
            mac_address,
            oui_data,
            last_signal_strength,
            last_recv,
            interactions: 0,
            ssid,
            client_list,
            channel: chan,
            beacon_count: 0,
            information: if let Some(info) = information {
                info
            } else {
                APFlags::default()
            },
            auth_sequence: AuthSequence::new(rogue_mac),
            has_hs: false,
            has_pmkid: false,
            is_target: false,
            is_whitelisted: false,
            wps_data
        }
    }

    // Check if the current time is passed the time stored in the t1 value + 5 seconds
    pub fn is_t1_elapsed(&self) -> bool {
        self.auth_sequence.is_t1_timeout()
    }

    // Set the timer_auth value to the current time
    pub fn update_t1_timer(&mut self) {
        self.auth_sequence.reset_t1();
    }

    // Check if the current time is passed the time stored in the t2 value + 0.2 seconds
    pub fn is_t2_elapsed(&self) -> bool {
        self.auth_sequence.is_t2_timeout()
    }

    // Set the t2 value to the current time
    pub fn update_t2_timer(&mut self) {
        self.auth_sequence.reset_t2();
    }

    pub fn is_hs_complete(&self) -> bool {
        if self.has_hs {
            return true;
        }
        false
    }

    pub fn is_target(&self) -> bool {
        self.is_target
    }

    pub fn is_whitelisted(&self) -> bool {
        self.is_whitelisted
    }

    pub fn to_json_str(&self) -> String {
        format!(
            "{{\"mac_address\": \"{}\",\"last_signal_strength\": \"{}\",\"last_recv\": \"{}\",\"interactions\": {},\"ssid\": \"{}\",\"channel\": {},\"client_list\": [{}],\"information\": {}, \"wps_info\": {},\"beacon_count\": {},\"has_hs\": {},\"has_pmkid\": {},\"is_target\": {},\"is_whitelisted\": {}}}",
            self.mac_address,
            self.last_signal_strength.value,
            epoch_to_iso_string(self.last_recv),
            self.interactions,
            self.ssid.as_ref().unwrap_or(&"".to_string()).clone(),
            self.channel
                .as_ref()
                .map_or("".to_string(), |ch| ch.short_string().to_string()),
            self.client_list.get_all_json(),
            self.information.to_json_str(),
            wps_to_json(&self.wps_data),
            self.beacon_count,
            self.has_hs,
            self.has_pmkid,
            self.is_target,
            self.is_whitelisted,
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct APFlags {
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

impl APFlags {
    pub fn to_json_str(&self) -> String {
        format!("{{\"apie_essid\": {},\"gs_ccmp\": {},\"gs_tkip\": {},\"cs_ccmp\": {},\"cs_tkip\": {},\"rsn_akm_psk\": {},\"rsn_akm_psk256\": {},\"rsn_akm_pskft\": {}, \"wpa_akm_psk\": {},\"ap_mfp\": {}}}", 
        option_bool_to_json_string(self.apie_essid), 
        option_bool_to_json_string(self.gs_ccmp), 
        option_bool_to_json_string(self.gs_tkip), 
        option_bool_to_json_string(self.cs_ccmp), 
        option_bool_to_json_string(self.cs_tkip), 
        option_bool_to_json_string(self.rsn_akm_psk), 
        option_bool_to_json_string(self.rsn_akm_psk256), 
        option_bool_to_json_string(self.rsn_akm_pskft), 
        option_bool_to_json_string(self.wpa_akm_psk), 
        option_bool_to_json_string(self.ap_mfp)
    )
    }

    // Checks if the AKM is PSK from any one of the indicators
    pub fn akm_mask(&self) -> bool {
        self.rsn_akm_psk.unwrap_or(false)
            || self.rsn_akm_psk256.unwrap_or(false)
            || self.rsn_akm_pskft.unwrap_or(false)
            || self.wpa_akm_psk.unwrap_or(false)
    }

    // Function to update capabilities with non-None values from another instance
    pub fn update_with(&mut self, other: &APFlags) {
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

/// Station - Associated or unassociated

#[derive(Clone, Debug)]
pub struct Station {
    pub mac_address: MacAddress,
    pub oui_data: Option<OuiRecord>,
    pub last_signal_strength: AntennaSignal,
    pub last_recv: u64,
    pub interactions: u64,
    pub access_point: Option<MacAddress>,
    pub aid: u16,
    pub probes: Option<Vec<String>>,
    pub timer_interact: SystemTime,
    pub has_rogue_m2: bool,
    pub rogue_actions: HashMap<String, bool>,
}

impl WiFiDeviceType for Station {}

// Default for station
impl Default for Station {
    fn default() -> Self {
        Station {
            mac_address: MacAddress([255, 255, 255, 255, 255, 255]),
            oui_data: None,
            last_signal_strength: AntennaSignal::from_bytes(&[0u8]).unwrap(),
            last_recv: 0,
            interactions: 0,
            access_point: None,
            aid: 0,
            probes: None,
            timer_interact: SystemTime::UNIX_EPOCH,
            has_rogue_m2: false,
            rogue_actions: HashMap::new(),
        }
    }
}

impl Station {
    pub fn new_station(
        mac_address: MacAddress,
        signal_strength: AntennaSignal,
        access_point: Option<MacAddress>,
        oui_info: Option<OuiRecord>,
    ) -> Station {
        Station {
            mac_address,
            oui_data: oui_info,
            last_signal_strength: signal_strength,
            last_recv: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs(),
            interactions: 0,
            access_point,
            aid: 0,
            probes: None,
            timer_interact: SystemTime::UNIX_EPOCH,
            has_rogue_m2: false,
            rogue_actions: HashMap::new(),
        }
    }

    pub fn new_unassoc_station(
        mac_address: MacAddress,
        signal_strength: AntennaSignal,
        probes: Vec<String>,
        oui_info: Option<OuiRecord>,
    ) -> Station {
        Station {
            mac_address,
            oui_data: oui_info,
            last_signal_strength: signal_strength,
            last_recv: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs(),
            interactions: 0,
            access_point: None,
            aid: 0,
            probes: Some(probes),
            timer_interact: SystemTime::UNIX_EPOCH,
            has_rogue_m2: false,
            rogue_actions: HashMap::new(),
        }
    }

    pub fn probes_to_string_list(&self) -> String {
        self.probes
            .as_ref()
            .unwrap_or(&Vec::new())
            .iter()
            .map(|ssid| ssid.to_string())
            .collect::<Vec<String>>()
            .join(", ")
    }

    pub fn probes_to_string_list_json(&self) -> String {
        self.probes
            .as_ref()
            .unwrap_or(&Vec::new())
            .iter()
            .map(|ssid| format!("\"{}\"", ssid.to_string()))
            .collect::<Vec<String>>()
            .join(",")
    }

    pub fn to_json_str(&self) -> String {
        format!(
            "{{\"mac_address\": \"{}\",\"last_signal_strength\": \"{}\",\"last_recv\": \"{}\",\"interactions\": {},\"probes\": [{}],\"has_rogue_m2\": {}}}",
            self.mac_address.to_string(),
            self.last_signal_strength.value.to_string(),
            epoch_to_iso_string(self.last_recv).to_string(),
            self.interactions,
            self.probes_to_string_list_json(),
            self.has_rogue_m2
        )
    }

    pub fn to_json_str_client(&self) -> String {
        format!(
            "{{\"mac_address\": \"{}\",\"last_signal_strength\": \"{}\",\"last_recv\": \"{}\",\"interactions\": {}}}",
            self.mac_address.to_string(),
            self.last_signal_strength.value.to_string(),
            epoch_to_iso_string(self.last_recv).to_string(),
            self.interactions
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct WiFiDeviceList<T: WiFiDeviceType> {
    devices: HashMap<MacAddress, T>,
    devices_sorted: Vec<T>,
}

// Common functions for any type of device
impl<T: WiFiDeviceType> WiFiDeviceList<T> {
    pub fn new() -> Self {
        WiFiDeviceList {
            devices: HashMap::new(),
            devices_sorted: Vec::new(),
        }
    }

    pub fn size(&self) -> usize {
        self.devices.len()
    }

    pub fn add_device(&mut self, mac_address: MacAddress, device: T) {
        self.devices.insert(mac_address, device);
    }

    pub fn get_random(&self) -> Option<&T> {
        let mut rng = thread_rng();
        self.devices.values().choose(&mut rng)
    }

    // Add a new device to the list
    pub fn remove_device(&mut self, mac: &MacAddress) {
        self.devices.remove(mac);
    }

    // Retrieve a device by MAC address
    pub fn get_device(&mut self, mac_address: &MacAddress) -> Option<&mut T> {
        self.devices.get_mut(mac_address)
    }

    // Retrieve a device by MAC address
    pub fn get_device_by_ssid(&mut self, ssid: &str) -> Option<&mut T>
    where
        T: HasSSID,
    {
        self.devices.values_mut().find_map(|x: &mut T| {
            if x.ssid().as_ref().map_or(false, |f| f == ssid) {
                Some(x)
            } else {
                None
            }
        })
    }

    // Retrieve a device by MAC address GLOB
    pub fn get_device_by_ssid_glob(&mut self, ssid: &str) -> Option<&mut T>
    where
        T: HasSSID,
    {
        self.devices.values_mut().find_map(|x: &mut T| {
            if let Some(device_ssid) = x.ssid() {
                if Glob::new(ssid)
                    .unwrap()
                    .compile_matcher()
                    .is_match(device_ssid)
                {
                    Some(x)
                } else {
                    None
                }
            } else {
                None
            }
        })
    }

    // Retrieve all devices
    pub fn get_devices(&mut self) -> &mut HashMap<MacAddress, T> {
        &mut self.devices
    }
}

// Functions specific to a WiFiDeviceList holding AccessPoints
impl WiFiDeviceList<AccessPoint> {
    pub fn get_all_clients(&self) -> HashMap<MacAddress, Station> {
        let mut all_clients = HashMap::new();

        for ap in self.devices.values() {
            for (mac, station) in &ap.client_list.devices {
                all_clients.insert(*mac, station.clone());
            }
        }

        all_clients
    }

    pub fn sort_devices(&mut self, sort: u8, sort_reverse: bool)  {
        let mut access_points: Vec<AccessPoint> = self
        .get_devices()
        .iter()
        .map(|(_, access_point)| access_point.clone())
        .collect();
    
        match sort {
            0 => access_points.sort_by(|a, b| {
                // TGT
                match (
                    a.is_target(),
                    a.is_whitelisted(),
                    b.is_target(),
                    b.is_whitelisted(),
                ) {
                    // Highest priority: is_target() = true, is_whitelist() = false
                    (true, false, _, _) => std::cmp::Ordering::Less,
                    (_, _, true, false) => std::cmp::Ordering::Greater,

                    // Middle priority: is_target() = false, is_whitelist() = false
                    (false, false, false, true) => std::cmp::Ordering::Less,
                    (false, true, false, false) => std::cmp::Ordering::Greater,

                    // Lowest priority: is_target() = false, is_whitelist() = true
                    // This case is covered implicitly by the previous matches

                    // Fallback for equal cases
                    _ => std::cmp::Ordering::Equal,
                }
            }),
            1 => access_points.sort_by(|a, b| b.channel.cmp(&a.channel)), // CH
            2 => access_points.sort_by(|a, b| {
                // RSSI
                let a_val = a.last_signal_strength.value;
                let b_val = b.last_signal_strength.value;

                match (a_val, b_val) {
                    // If both values are the same (and it doesn't matter if they are zero or not)
                    _ if a_val == b_val => std::cmp::Ordering::Equal,

                    // Prioritize any non-zero value over zero
                    (0, _) => std::cmp::Ordering::Greater, // A is worse if it's zero
                    (_, 0) => std::cmp::Ordering::Less,    // B is worse if it's zero

                    // Otherwise, just do a normal comparison
                    _ => b_val.cmp(&a_val),
                }
            }),
            3 => access_points.sort_by(|a, b| b.last_recv.cmp(&a.last_recv)), // Last
            4 => access_points.sort_by(|a, b| b.client_list.size().cmp(&a.client_list.size())), // Clients
            5 => access_points.sort_by(|a, b| b.interactions.cmp(&a.interactions)), // Tx
            6 => access_points.sort_by(|a, b| b.has_hs.cmp(&a.has_hs)),             // HS
            7 => access_points.sort_by(|a, b| b.has_pmkid.cmp(&a.has_pmkid)),       // PM
            _ => {
                access_points.sort_by(|a, b| b.last_recv.cmp(&a.last_recv));
            }
        }

        if sort_reverse {
            access_points.reverse();
        }
        self.devices_sorted = access_points;
    }

    pub fn get_devices_sorted(&self) -> &Vec<AccessPoint> {
        &self.devices_sorted
    }

    pub fn clear_all_interactions(&mut self) {
        for dev in self.devices.values_mut() {
            dev.interactions = 0;
        }
    }

    pub fn find_ap_by_client_mac(&mut self, client_mac: &MacAddress) -> Option<&mut AccessPoint> {
        let ap_mac_address = self
            .devices
            .iter()
            .find(|(_mac, ap)| ap.client_list.devices.contains_key(client_mac))
            .map(|(mac, _)| *mac);

        ap_mac_address.and_then(move |mac| self.devices.get_mut(&mac))
    }

    pub fn add_or_update_device(
        &mut self,
        mac_address: MacAddress,
        new_ap: &AccessPoint,
    ) -> &mut AccessPoint {
        if self.devices.contains_key(&mac_address) {
            let ap = self.devices.get_mut(&mac_address).unwrap();
            // Update the existing access point
            ap.last_recv = new_ap.last_recv;
            if new_ap.last_signal_strength != AntennaSignal::from_bytes(&[0u8]).unwrap() {
                ap.last_signal_strength = new_ap.last_signal_strength;
            }

            // Update the channel
            if new_ap.channel.is_some() {
                ap.channel = new_ap.channel.clone();
            }

            // Update clients
            for (mac, client) in &new_ap.client_list.devices {
                ap.client_list.add_or_update_device(*mac, client);
            }

            if let Some(nssid) = &new_ap.ssid {
                let new_ssid = nssid.replace('\0', "");
                // Update SSID
                if ap.ssid.is_none() || ap.ssid.as_mut().is_some_and(|ssid| ssid.is_empty()) {
                    ap.ssid = Some(new_ssid);
                }
            }
            // Update information
            ap.information.update_with(&new_ap.information);

            // Update WPS info
            if let Some(orig) = &mut ap.wps_data {
                if let Some(new_data) = &new_ap.wps_data {
                    orig.update_with(new_data);
                }
            } else {
                ap.wps_data = new_ap.wps_data.clone();
            }
            return ap;
        }
        // Add a new access point
        self.devices.insert(mac_address, new_ap.clone());
        self.devices.get_mut(&mac_address).unwrap()
    }

    pub fn get_table(
        &mut self,
        selected_row: Option<usize>,
        sort: u8,
        sort_reverse: bool,
    ) -> (Vec<String>, Vec<(Vec<String>, u16)>) {
        // Header fields
        let headers = vec![
            "TGT".to_string(),
            "MAC Address".to_string(),
            "CH".to_string(),
            "RSSI".to_string(),
            "Last".to_string(),
            "SSID".to_string(),
            "Clients".to_string(),
            "Tx".to_string(),
            "4wHS".to_string(),
            "PMKID".to_string(),
        ];

        self.sort_devices(sort, sort_reverse);
        let access_points = &self.devices_sorted;

        let mut rows: Vec<(Vec<String>, u16)> = Vec::new();
        for (idx, ap) in access_points.iter().enumerate() {
            let mut ap_row = vec![
                format!(
                    "{}",
                    if ap.is_target() {
                        "\u{274E}"
                    } else if ap.is_whitelisted() {
                        "\u{2B1C}"
                    } else {
                        ""
                    }
                ), // TGT
                format!("{}", ap.mac_address), // MAC Address
                ap.channel
                    .as_ref()
                    .map_or("".to_string(), |ch| ch.short_string().to_string()), // CH
                format!(
                    "{}",
                    match ap.last_signal_strength.value {
                        0 => "".to_string(),
                        _ => ap.last_signal_strength.value.to_string(),
                    }
                ), // RSSI
                format!("{}", epoch_to_string(ap.last_recv).to_string()), // Last
                ap.ssid.as_ref().unwrap_or(&"".to_string()).clone(), // SSID
                format!("{}", ap.client_list.size()), // Clients
                format!("{}", ap.interactions), // Tx
                if ap.has_hs {
                    "\u{2705}".to_string()
                } else {
                    " ".to_string()
                }, // 4wHS
                if ap.has_pmkid {
                    "\u{2705}".to_string()
                } else {
                    " ".to_string()
                }, // PMKID
            ];
            let mut height = 1;
            if selected_row.is_some() && idx == selected_row.unwrap() {
                height = 4;
                for _ in 0..3 {
                    for col in &mut ap_row {
                        col.push('\n');
                    }
                }
                if ap.client_list.size() >= 1 {
                    height += 1;
                    ap_row = add_client_header(ap_row);
                    for (idx, client) in ap.client_list.clone().get_devices().values().enumerate() {
                        let last = idx == ap.client_list.size() - 1;
                        let merged = add_client_rows(ap_row, client, last);
                        ap_row = merged;
                        height += 1;
                    }
                }
            }
            rows.push((ap_row, height));
        }
        (headers, rows)
    }
}

fn add_client_header(ap_row: Vec<String>) -> Vec<String> {
    let mut merged = Vec::with_capacity(ap_row.len());

    let new_str: String = format!("{}\n", ap_row[0]);
    merged.push(new_str);

    let new_str: String = format!("{}\nClients", ap_row[1]);
    merged.push(new_str);

    let new_str: String = format!("{}\n", ap_row[2]);
    merged.push(new_str);

    let new_str: String = format!("{}\n", ap_row[3]);
    merged.push(new_str);

    let new_str: String = format!("{}\n", ap_row[4]);
    merged.push(new_str);

    let new_str: String = format!("{}\n", ap_row[5]);
    merged.push(new_str);

    let new_str: String = format!("{}\n", ap_row[6]);
    merged.push(new_str);

    let new_str: String = format!("{}\n", ap_row[7]);
    merged.push(new_str);

    let new_str: String = format!("{}\n", ap_row[8]);
    merged.push(new_str);

    let new_str: String = format!("{}\n", ap_row[9]);
    merged.push(new_str);

    merged
}

fn add_client_rows(ap_row: Vec<String>, client: &Station, last: bool) -> Vec<String> {
    let min_length = ap_row.len();
    let icon = if last { "└ " } else { "├ " };

    let mut merged = Vec::with_capacity(min_length);

    // TGT 8
    let new_str: String = ap_row[0].to_string();
    merged.push(new_str);
    // Mac Address 1
    let new_str: String = format!("{}\n  {}{}", ap_row[1], icon, client.mac_address);
    merged.push(new_str);
    // Channel 2
    let new_str: String = ap_row[2].to_string();
    merged.push(new_str);
    // RSSI 3
    let new_str: String = format!(
        "{}\n{}",
        ap_row[3],
        match client.last_signal_strength.value {
            0 => "".to_string(),
            _ => client.last_signal_strength.value.to_string(),
        }
    );
    merged.push(new_str);
    // Last 4
    let new_str: String = format!("{}\n{}", ap_row[4], epoch_to_string(client.last_recv));
    merged.push(new_str);
    // SSID 5
    let new_str: String = ap_row[5].to_string();
    merged.push(new_str);
    // Clients 6
    let new_str: String = ap_row[6].to_string();
    merged.push(new_str);
    // TX 7
    let new_str: String = format!("{}\n{}", ap_row[7], client.interactions);
    merged.push(new_str);
    // 4wHS 8
    let new_str: String = ap_row[8].to_string();
    merged.push(new_str);
    // PMKID 9
    let new_str: String = ap_row[9].to_string();
    merged.push(new_str);

    merged
}

fn add_probe_rows(
    cl_row: Vec<String>,
    probe: &String,
    last: bool,
    rogue_collected: bool,
) -> Vec<String> {
    let min_length = cl_row.len();
    let icon = if last { "└ " } else { "├ " };
    let check = if rogue_collected {
        "\u{2714}".to_string()
    } else {
        " ".to_string()
    };

    let mut merged = Vec::with_capacity(min_length);

    // Mac Address 0
    let new_str: String = format!("{}\n  {}{}", cl_row[0], icon, probe);
    merged.push(new_str);

    // RSSI 1
    let new_str: String = cl_row[1].to_string();
    merged.push(new_str);

    // Last 2
    let new_str: String = cl_row[2].to_string();
    merged.push(new_str);

    // Tx 3
    let new_str: String = cl_row[3].to_string();
    merged.push(new_str);

    // Rogue 4
    let new_str: String = format!("{}\n{}", cl_row[4], check);
    merged.push(new_str);

    // Probes 5
    let new_str: String = cl_row[5].to_string();
    merged.push(new_str);

    merged
}

// Functions specific to a WiFiDeviceList holding Stations
impl WiFiDeviceList<Station> {
    pub fn sort_devices(&mut self, sort: u8, sort_reverse: bool)  {
        let mut stations: Vec<_> = self
            .get_devices()
            .iter()
            .map(|(_, station)| station.clone())
            .collect();

        match sort {
            0 => stations.sort_by(|a, b| b.last_recv.cmp(&a.last_recv)), // 2
            1 => stations.sort_by(|a, b| {
                // 1
                let a_val = a.last_signal_strength.value;
                let b_val = b.last_signal_strength.value;

                match (a_val, b_val) {
                    // If both values are the same (and it doesn't matter if they are zero or not)
                    _ if a_val == b_val => std::cmp::Ordering::Equal,

                    // Prioritize any non-zero value over zero
                    (0, _) => std::cmp::Ordering::Greater, // A is worse if it's zero
                    (_, 0) => std::cmp::Ordering::Less,    // B is worse if it's zero

                    // Otherwise, just do a normal comparison
                    _ => b_val.cmp(&a_val),
                }
            }),
            2 => stations.sort_by(|a, b| b.interactions.cmp(&a.interactions)), // 3
            3 => stations.sort_by(|a, b| b.has_rogue_m2.cmp(&a.has_rogue_m2)), // 4
            4 => stations.sort_by(|a, b| {
                // 5
                b.probes
                    .as_ref()
                    .map_or(0, |v| v.len())
                    .cmp(&a.probes.as_ref().map_or(0, |v| v.len()))
            }),
            _ => {
                stations.sort_by(|a, b| b.last_recv.cmp(&a.last_recv));
            }
        }

        if sort_reverse {
            stations.reverse();
        }
        self.devices_sorted = stations;
    }

    pub fn get_devices_sorted(&self) -> &Vec<Station> {
        &self.devices_sorted
    }

    pub fn get_table(
        &mut self,
        selected_row: Option<usize>,
        sort: u8,
        sort_reverse: bool
    ) -> (Vec<String>, Vec<(Vec<String>, u16)>) {
        // Header fields
        //"MAC Address", "RSSI", "Last", Tx, "Probes"
        let headers = vec![
            "MAC Address".to_string(),
            "RSSI".to_string(),
            "Last".to_string(),
            "Tx".to_string(),
            "Rogue M2".to_string(),
            "Probes".to_string(),
        ];

        // Make our stations object
        self.sort_devices(sort, sort_reverse);
        let stations = &self.devices_sorted;

        let mut rows: Vec<(Vec<String>, u16)> = Vec::new();
        for (idx, station) in stations.iter().enumerate() {
            let mut height = 1;

            // Row is currently selected.
            let mut cl_row = vec![
                format!("{}", station.mac_address), // MAC Address
                format!(
                    "{}",
                    match station.last_signal_strength.value {
                        0 => "".to_string(),
                        _ => station.last_signal_strength.value.to_string(),
                    }
                ), // RSSI
                format!("{}", epoch_to_string(station.last_recv).to_string()), // Last
                format!("{}", station.interactions), // Tx
                if station.has_rogue_m2 {
                    // Rogue M2
                    "\u{2705}".to_string()
                } else {
                    " ".to_string()
                },
                format!("{}", station.probes.as_ref().map_or(0, |v| v.len())), // MFP
            ];

            if selected_row.is_some() && idx == selected_row.unwrap() {
                if let Some(probes) = &station.probes {
                    for (idx, probe) in probes.iter().enumerate() {
                        let last = idx == probes.len() - 1;
                        let merged = add_probe_rows(
                            cl_row,
                            probe,
                            last,
                            station.rogue_actions.get(probe).is_some_and(|f| *f),
                        );
                        cl_row = merged;
                        height += 1;
                    }
                }
            }
            rows.push((cl_row, height));
        }
        (headers, rows)
    }

    pub fn add_or_update_device(
        &mut self,
        mac_address: MacAddress,
        new_station: &Station,
    ) -> &mut Station {
        let exists = self.devices.contains_key(&mac_address);
        if exists {
            let station = self.devices.get_mut(&mac_address).unwrap();
            // Update the existing station's last received time and signal strength
            station.last_recv = new_station.last_recv;
            if new_station.last_signal_strength != AntennaSignal::from_bytes(&[0u8]).unwrap() {
                station.last_signal_strength = new_station.last_signal_strength;
            }

            // Update the station's probes
            if let Some(new_probes) = &new_station.probes {
                let probes = station.probes.get_or_insert_with(Vec::new);
                for new_probe in new_probes {
                    if !probes.contains(new_probe) {
                        probes.push(new_probe.to_string());
                    }
                }
            }
            station
        } else {
            self.devices.insert(mac_address, new_station.clone());
            self.devices.get_mut(&mac_address).unwrap()
        }
    }

    pub fn clear_all_interactions(&mut self) {
        for dev in self.devices.values_mut() {
            dev.interactions = 0;
        }
    }

    pub fn get_all_json(&self) -> String {
        let mut strings: Vec<String> = Vec::new();
        for client in &self.devices {
            strings.push(client.1.to_json_str_client())
        }
        strings.join(",")
    }
}
