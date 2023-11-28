use crate::ntlook::WiFiChannel;
use libwifi::frame::components::MacAddress;
use radiotap::field::{AntennaSignal, Field};
use rand::seq::IteratorRandom;
use rand::thread_rng;
use std::collections::HashMap;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

//////////////////////////////////////////////////////////////////////

// Trait to restrict WiFiDeviceList
pub trait WiFiDeviceType {}

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
    pub timer_auth: SystemTime,
}

impl WiFiDeviceType for AccessPoint {}

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
            timer_auth: SystemTime::now(),
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
            timer_auth: SystemTime::now(),
        }
    }

    pub fn new_with_clients(
        mac_address: MacAddress,
        last_signal_strength: AntennaSignal,
        ssid: Option<String>,
        channel: Option<u8>,
        information: Option<APFlags>,
        client_list: WiFiDeviceList<Station>,
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
            timer_auth: SystemTime::now(),
        }
    }

    // Check if the current time is passed the time stored in the timer_auth value + 0.2 seconds
    pub fn is_auth_time_elapsed(&self) -> bool {
        match SystemTime::now().duration_since(self.timer_auth) {
            Ok(elapsed) => elapsed > Duration::from_millis(200),
            Err(_) => false, // Handle case where current time is earlier than timer_auth
        }
    }

    // Set the timer_auth value to the current time
    pub fn update_auth_timer(&mut self) {
        self.timer_auth = SystemTime::now();
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

    pub fn size(&mut self) -> usize {
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
        let exists = self.devices.contains_key(&mac_address);
        if exists {
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

            // Update other fields
            if ap.ssid.is_none() {
                ap.ssid = new_ap.ssid.clone();
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
