use globset::Glob;
use libwifi::frame::components::MacAddress;
use rand::seq::SliceRandom;

use crate::devices::AccessPoint;

trait IsTarget {
    fn target_match(&self, ap: &AccessPoint) -> bool;
}

#[derive(Eq, PartialEq, Hash, Clone)]
pub struct TargetSSID {
    pub ssid: String,
}

impl IsTarget for TargetSSID {
    fn target_match(&self, ap: &AccessPoint) -> bool {
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

impl TargetSSID {
    pub fn new(ssid: &str) -> Self {
        TargetSSID {
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

#[derive(Eq, PartialEq, Hash, Clone)]
pub struct TargetMAC {
    pub addr: MacAddress,
}

impl IsTarget for TargetMAC {
    fn target_match(&self, ap: &AccessPoint) -> bool {
        if ap.mac_address == self.addr {
            return true;
        }
        false
    }
}

impl TargetMAC {
    pub fn new(addr: MacAddress) -> Self {
        TargetMAC { addr }
    }
}
#[derive(Eq, PartialEq, Hash, Clone)]
pub enum Target {
    MAC(TargetMAC),
    SSID(TargetSSID),
}

impl Target {
    pub fn get_string(&self) -> String {
        match self {
            Target::MAC(tgt) => tgt.addr.to_string(),
            Target::SSID(tgt) => tgt.ssid.clone(),
        }
    }
}

pub struct TargetList {
    targets: Vec<Target>,
}

impl TargetList {
    pub fn new() -> Self {
        TargetList {
            targets: Vec::new(),
        }
    }

    pub fn from_vec(targets: Vec<Target>) -> Self {
        TargetList { targets }
    }

    pub fn add(&mut self, target: Target) {
        self.targets.push(target);
    }

    pub fn empty(&self) -> bool {
        self.targets.is_empty()
    }

    /// Will check if the AP is a target, but will also mark the
    pub fn is_target(&mut self, ap: &mut AccessPoint) -> bool {
        if self.empty() {
            return true;
        };

        for target in &self.targets {
            match target {
                Target::MAC(tgt) => {
                    if tgt.target_match(ap) {
                        if let Some(ssid) = &ap.ssid {
                            if !self.is_target_ssid(ssid) {
                                self.add(Target::SSID(TargetSSID {
                                    ssid: ssid.to_string(),
                                }));
                            }
                        }
                        ap.is_target = true;
                        return true;
                    }
                }
                Target::SSID(tgt) => {
                    if tgt.target_match(ap) {
                        if !self.is_target_mac(&ap.mac_address) {
                            self.add(Target::MAC(TargetMAC {
                                addr: ap.mac_address,
                            }))
                        }
                        ap.is_target = true;
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn get_target(&mut self, ap: &mut AccessPoint) -> Result<Target, ()> {
        if self.empty() {
            return Err(());
        };

        for target in self.targets.clone() {
            match target {
                Target::MAC(ref tgt) => {
                    if tgt.target_match(ap) {
                        if let Some(ssid) = &ap.ssid {
                            if !self.is_target_ssid(ssid) {
                                self.add(Target::SSID(TargetSSID {
                                    ssid: ssid.to_string(),
                                }));
                            }
                        }
                        ap.is_target = true;
                        return Ok(target);
                    }
                }
                Target::SSID(ref tgt) => {
                    if tgt.target_match(ap) {
                        if !self.is_target_mac(&ap.mac_address) {
                            self.add(Target::MAC(TargetMAC {
                                addr: ap.mac_address,
                            }))
                        }
                        ap.is_target = true;
                        return Ok(target);
                    }
                }
            }
        }
        Err(())
    }

    pub fn is_target_mac(&self, mac: &MacAddress) -> bool {
        if self.empty() {
            return true;
        };

        for target in &self.targets {
            match target {
                Target::MAC(tgt) => {
                    if tgt.addr == *mac {
                        return true;
                    }
                }
                Target::SSID(_) => {} // do nothing
            }
        }
        false
    }

    pub fn is_target_ssid(&self, ssid: &str) -> bool {
        if self.empty() {
            return true;
        };

        for target in &self.targets {
            match target {
                Target::MAC(_) => {} // do nothing, we don't have anything to compare to here.
                Target::SSID(tgt) => {
                    if tgt.match_ssid(ssid.to_owned()) {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn has_ssid(&self) -> bool {
        for target in &self.targets {
            match target {
                Target::MAC(_) => continue,
                Target::SSID(_) => return true,
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
            let tgt = self.targets.choose(&mut rand::thread_rng()).unwrap();
            if let Target::SSID(tgt) = tgt {
                return Some(tgt.ssid.clone());
            }
        }
    }

    pub fn get_string(&self) -> String {
        self.targets
            .iter()
            .map(|target| match target {
                Target::MAC(mac_target) => format!("MAC: {}", mac_target.addr),
                Target::SSID(ssid_target) => format!("SSID: {}", ssid_target.ssid),
            })
            .collect::<Vec<String>>()
            .join(", ")
    }

    pub fn get_ref(&self) -> &Vec<Target> {
        &self.targets
    }
}
