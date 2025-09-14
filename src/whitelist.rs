use globset::Glob;
use libwifi::frame::components::MacAddress;
use rand::seq::SliceRandom;

use crate::devices::AccessPoint;

trait IsWhitelisted {
    fn whitelist_match(&self, ap: &AccessPoint) -> bool;
}

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub struct WhiteSSID {
    pub ssid: String,
}

impl IsWhitelisted for WhiteSSID {
    fn whitelist_match(&self, ap: &AccessPoint) -> bool {
        if let Some(ssid) = ap.ssid.clone() {
            if Glob::new(&self.ssid)
                .unwrap()
                .compile_matcher()
                .is_match(ssid)
            {
                return true;
            }
        }
        false
    }
}

impl WhiteSSID {
    pub fn new(ssid: &str) -> Self {
        WhiteSSID {
            ssid: ssid.to_owned(),
        }
    }

    fn match_ssid(&self, ssid: String) -> bool {
        if ssid == self.ssid {
            return true;
        }
        false
    }
}

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub struct WhiteMAC {
    pub addr: MacAddress,
}

impl IsWhitelisted for WhiteMAC {
    fn whitelist_match(&self, ap: &AccessPoint) -> bool {
        if ap.mac_address == self.addr {
            return true;
        }
        false
    }
}

impl WhiteMAC {
    pub fn new(addr: MacAddress) -> Self {
        WhiteMAC { addr }
    }
}
#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub enum White {
    Mac(WhiteMAC),
    Ssid(WhiteSSID),
}

impl White {
    pub fn get_string(&self) -> String {
        match self {
            White::Mac(tgt) => tgt.addr.to_string(),
            White::Ssid(tgt) => tgt.ssid.clone(),
        }
    }
}

pub struct WhiteList {
    devices: Vec<White>,
}

impl WhiteList {
    pub fn new() -> Self {
        WhiteList {
            devices: Vec::new(),
        }
    }

    pub fn from_vec(devices: Vec<White>) -> Self {
        WhiteList { devices }
    }

    pub fn add(&mut self, device: White) {
        self.devices.push(device);
    }

    pub fn empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Will check if the AP is a target, but will also mark the
    pub fn is_whitelisted(&mut self, ap: &mut AccessPoint) -> bool {
        if self.empty() {
            return false;
        };

        for device in &self.devices {
            match device {
                White::Mac(tgt) => {
                    if tgt.whitelist_match(ap) {
                        if let Some(ssid) = &ap.ssid {
                            if !self.is_whitelisted_ssid(ssid) {
                                self.add(White::Ssid(WhiteSSID {
                                    ssid: ssid.to_string(),
                                }));
                            }
                        }
                        if !ap.is_target() {
                            ap.is_whitelisted = true;
                        }
                        return true;
                    }
                }
                White::Ssid(tgt) => {
                    if tgt.whitelist_match(ap) {
                        if !self.is_whitelisted_mac(&ap.mac_address) {
                            self.add(White::Mac(WhiteMAC {
                                addr: ap.mac_address,
                            }))
                        }
                        if !ap.is_target() {
                            ap.is_whitelisted = true;
                        }
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn get_whitelisted(&mut self, ap: &mut AccessPoint) -> Vec<White> {
        if self.empty() {
            return vec![];
        };
        let mut matches: Vec<White> = Vec::new();

        for target in self.devices.clone() {
            match target {
                White::Mac(ref tgt) => {
                    if tgt.whitelist_match(ap) {
                        if let Some(ssid) = &ap.ssid {
                            if !self.is_whitelisted_ssid(ssid) {
                                self.add(White::Ssid(WhiteSSID {
                                    ssid: ssid.to_string(),
                                }));
                            }
                        }
                        if !ap.is_target() {
                            ap.is_whitelisted = true;
                        }
                        matches.push(target);
                    }
                }
                White::Ssid(ref tgt) => {
                    if tgt.whitelist_match(ap) {
                        if !self.is_whitelisted_mac(&ap.mac_address) {
                            self.add(White::Mac(WhiteMAC {
                                addr: ap.mac_address,
                            }))
                        }
                        if !ap.is_target() {
                            ap.is_whitelisted = true;
                        }
                        matches.push(target);
                    }
                }
            }
        }
        matches
    }

    pub fn is_whitelisted_mac(&self, mac: &MacAddress) -> bool {
        if self.empty() {
            return true;
        };

        for target in &self.devices {
            match target {
                White::Mac(tgt) => {
                    if tgt.addr == *mac {
                        return true;
                    }
                }
                White::Ssid(_) => {} // do nothing
            }
        }
        false
    }

    pub fn is_whitelisted_ssid(&self, ssid: &str) -> bool {
        if self.empty() {
            return true;
        };

        for target in &self.devices {
            match target {
                White::Mac(_) => {} // do nothing, we don't have anything to compare to here.
                White::Ssid(tgt) => {
                    if tgt.match_ssid(ssid.to_owned()) {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn has_ssid(&self) -> bool {
        for device in &self.devices {
            match device {
                White::Mac(_) => continue,
                White::Ssid(_) => return true,
            }
        }
        false
    }

    pub fn get_random_ssid(&self) -> Option<String> {
        if self.empty() {
            return None;
        }
        if !self.has_ssid() {
            return None;
        }
        loop {
            let tgt = self.devices.choose(&mut rand::thread_rng()).unwrap();
            if let White::Ssid(tgt) = tgt {
                return Some(tgt.ssid.clone());
            }
        }
    }

    pub fn get_string(&self) -> String {
        self.devices
            .iter()
            .map(|target| match target {
                White::Mac(mac_target) => format!("MAC: {}", mac_target.addr),
                White::Ssid(ssid_target) => format!("SSID: {}", ssid_target.ssid),
            })
            .collect::<Vec<String>>()
            .join(", ")
    }

    pub fn get_ref(&self) -> &Vec<White> {
        &self.devices
    }
}
