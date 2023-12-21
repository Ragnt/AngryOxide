use libwifi::frame::components::MacAddress;
use nl80211_ng::channels::WiFiChannel;
use radiotap::field::{AntennaSignal, Field};
use rand::seq::IteratorRandom;
use rand::thread_rng;
use std::collections::HashMap;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
        }
    }
}

impl AccessPoint {
    pub fn new(
        mac_address: MacAddress,
        last_signal_strength: AntennaSignal,
        ssid: Option<String>,
        channel: Option<u8>,
        information: Option<APFlags>,
        rogue_mac: MacAddress,
    ) -> Self {
        let client_list = WiFiDeviceList::new();
        let last_recv = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let chan = if let Some(channel) = channel {
            WiFiChannel::new(channel)
        } else {
            None
        };

        AccessPoint {
            mac_address,
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
        }
    }

    pub fn new_with_clients(
        mac_address: MacAddress,
        last_signal_strength: AntennaSignal,
        ssid: Option<String>,
        channel: Option<u8>,
        information: Option<APFlags>,
        client_list: WiFiDeviceList<Station>,
        rogue_mac: MacAddress,
    ) -> Self {
        let last_recv = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let chan = if let Some(channel) = channel {
            WiFiChannel::new(channel)
        } else {
            None
        };

        AccessPoint {
            mac_address,
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
        return false;
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
    pub last_signal_strength: AntennaSignal,
    pub last_recv: u64,
    pub interactions: u64,
    pub access_point: Option<MacAddress>,
    pub aid: u16,
    pub probes: Option<Vec<String>>,
    pub timer_auth: SystemTime,
    pub timer_assoc: SystemTime,
    pub timer_reassoc: SystemTime,
    pub has_rogue_m2: bool,
}

impl WiFiDeviceType for Station {}

// Default for station
impl Default for Station {
    fn default() -> Self {
        Station {
            mac_address: MacAddress([255, 255, 255, 255, 255, 255]),
            last_signal_strength: AntennaSignal::from_bytes(&[0u8]).unwrap(),
            last_recv: 0,
            interactions: 0,
            access_point: None,
            aid: 0,
            probes: None,
            timer_auth: SystemTime::now(),
            timer_assoc: SystemTime::now(),
            timer_reassoc: SystemTime::now(),
            has_rogue_m2: false,
        }
    }
}

impl Station {
    pub fn new_station(
        mac_address: MacAddress,
        signal_strength: AntennaSignal,
        access_point: Option<MacAddress>,
    ) -> Station {
        Station {
            mac_address,
            last_signal_strength: signal_strength,
            last_recv: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs(),
            interactions: 0,
            access_point,
            aid: 0,
            probes: None,
            timer_auth: SystemTime::now(),
            timer_assoc: SystemTime::now(),
            timer_reassoc: SystemTime::now(),
            has_rogue_m2: false,
        }
    }

    pub fn new_unassoc_station(
        mac_address: MacAddress,
        signal_strength: AntennaSignal,
        probes: Vec<String>,
    ) -> Station {
        Station {
            mac_address,
            last_signal_strength: signal_strength,
            last_recv: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs(),
            interactions: 0,
            access_point: None,
            aid: 0,
            probes: Some(probes),
            timer_auth: SystemTime::now(),
            timer_assoc: SystemTime::now(),
            timer_reassoc: SystemTime::now(),
            has_rogue_m2: false,
        }
    }

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

#[derive(Clone, Debug, Default)]
pub struct WiFiDeviceList<T: WiFiDeviceType> {
    devices: HashMap<MacAddress, T>,
}

// Common functions for any type of device
impl<T: WiFiDeviceType> WiFiDeviceList<T> {
    pub fn new() -> Self {
        WiFiDeviceList {
            devices: HashMap::new(),
        }
    }

    pub fn add_device(&mut self, mac_address: MacAddress, device: T) {
        self.devices.insert(mac_address, device);
    }

    pub fn size(&self) -> usize {
        self.devices.len()
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
        self.devices
            .values_mut() // Get a mutable iterator over the values
            .find_map(|x: &mut T| {
                if x.ssid().as_ref().map_or(false, |f| f == ssid) {
                    Some(x)
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

            // Update clients
            for (mac, client) in &new_ap.client_list.devices {
                ap.client_list.add_or_update_device(*mac, client);
            }

            if let Some(nssid) = &new_ap.ssid {
                let new_ssid = nssid.replace('\0', "");
                // Update other fields
                if ap.ssid.is_none() {
                    ap.ssid = Some(new_ssid);
                } else if ap.ssid.clone().unwrap() == "" {
                    let _ = "";
                    ap.ssid = Some(new_ssid);
                }
            }
            ap.information.update_with(&new_ap.information);
            return ap;
        }
        // Add a new access point
        self.devices.insert(mac_address, new_ap.clone());
        self.devices.get_mut(&mac_address).unwrap()
    }
}

// Functions specific to a WiFiDeviceList holding Stations
impl WiFiDeviceList<Station> {
    pub fn add_or_update_device(
        &mut self,
        mac_address: MacAddress,
        new_station: &Station,
    ) -> &Station {
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
}
