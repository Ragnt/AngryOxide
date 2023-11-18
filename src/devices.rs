use libwifi::frame::components::MacAddress;
use radiotap::field::{AntennaSignal, Field};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
// Define a struct for general WiFi device properties
pub struct WiFiDevice {
    pub mac_address: MacAddress,             // MAC address of the device
    pub last_signal_strength: AntennaSignal, // Signal strength in dBm
    pub last_recv: u64,                      // Timestamp of the last received frame in epoch
    pub device_type: WiFiDeviceType,         // Device type with unique properties
}

// Enum for different WiFi device types
#[derive(Clone, Debug)]
pub enum WiFiDeviceType {
    AccessPoint(AccessPointData),
    Station(StationData),
}

// Struct to represent unique data for Access Points
#[derive(Clone, Debug)]
pub struct AccessPointData {
    pub ssid: Option<String>,        // SSID of the Access Point
    pub client_list: WiFiDeviceList, // List of connected clients (Stations)
}
#[derive(Clone, Debug)]
pub struct StationData {
    pub aid: Option<u16>,
    pub probes: Option<Vec<String>>, // directed probes by device
}

impl StationData {
    pub fn probes_to_string_list(&mut self) -> String {
        self.probes
            .as_ref()
            .unwrap()
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
    ) -> WiFiDevice {
        let client_list = WiFiDeviceList::new();
        let current_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        WiFiDevice {
            mac_address,
            last_signal_strength: signal_strength,
            last_recv: current_epoch,
            device_type: WiFiDeviceType::AccessPoint(AccessPointData { ssid, client_list }),
        }
    }

    pub fn new_access_point_with_client(
        mac_address: MacAddress,
        signal_strength: AntennaSignal,
        ssid: Option<String>,
        clients: Vec<WiFiDevice>,
    ) -> WiFiDevice {
        let mut client_list = WiFiDeviceList::new();
        for cl in clients {
            client_list.add_device(cl);
        }
        let current_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        WiFiDevice {
            mac_address,
            last_signal_strength: signal_strength,
            last_recv: current_epoch,
            device_type: WiFiDeviceType::AccessPoint(AccessPointData { ssid, client_list }),
        }
    }

    // Constructor for Station
    pub fn new_station(
        mac_address: MacAddress,
        signal_strength: AntennaSignal,
        aid: Option<u16>,
    ) -> WiFiDevice {
        let current_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        WiFiDevice {
            mac_address,
            last_signal_strength: signal_strength,
            last_recv: current_epoch,
            device_type: WiFiDeviceType::Station(StationData { aid, probes: None }),
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
            device_type: WiFiDeviceType::Station(StationData {
                aid: None,
                probes: Some(probes),
            }),
        }
    }
}

#[derive(Debug, Clone)]
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
                            for probe in newdata.probes.unwrap_or(vec![]) {
                                if !probes.contains(&probe) {
                                    probes.push(probe);
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

    // Modify a device
    pub fn modify_device<F>(&mut self, mac_address: &MacAddress, modify: F)
    where
        F: FnOnce(&mut WiFiDevice),
    {
        if let Some(device) = self.devices.get_mut(mac_address) {
            modify(device);
        }
    }
}
