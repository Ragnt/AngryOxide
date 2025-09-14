use globset::Glob;
use libwifi::frame::components::MacAddress;
use rand::seq::SliceRandom;

use crate::devices::AccessPoint;

trait IsTarget {
    fn target_match(&self, ap: &AccessPoint) -> bool;
}

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
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

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
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
#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub enum Target {
    Mac(TargetMAC),
    Ssid(TargetSSID),
}

impl Target {
    pub fn get_string(&self) -> String {
        match self {
            Target::Mac(tgt) => tgt.addr.to_string(),
            Target::Ssid(tgt) => tgt.ssid.clone(),
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

    /// Remove *exactly* the provided `Target`.
    /// Returns `true` if something was deleted.
    pub fn remove(&mut self, target: &Target) -> bool {
        let before = self.targets.len();
        self.targets.retain(|t| t != target);
        before != self.targets.len()
    }

    /// Remove every stored MAC equal to `mac`.
    pub fn remove_mac(&mut self, mac: &MacAddress) -> bool {
        let before = self.targets.len();
        self.targets
            .retain(|t| !matches!(t, Target::Mac(tgt) if tgt.addr == *mac));
        before != self.targets.len()
    }

    /// Remove every stored SSID equal to `ssid`.
    pub fn remove_ssid(&mut self, ssid: &str) -> bool {
        let before = self.targets.len();
        self.targets
            .retain(|t| !matches!(t, Target::Ssid(tgt) if tgt.ssid == ssid));
        before != self.targets.len()
    }

    pub fn empty(&self) -> bool {
        self.targets.is_empty()
    }

    /// Will check if the AP is a target
    pub fn is_target(&mut self, ap: &mut AccessPoint) -> bool {
        if self.empty() {
            return true;
        };

        for target in &self.targets {
            match target {
                Target::Mac(tgt) => {
                    if tgt.target_match(ap) {
                        if let Some(ssid) = &ap.ssid {
                            if !self.is_target_ssid(ssid) {
                                self.add(Target::Ssid(TargetSSID {
                                    ssid: ssid.to_string(),
                                }));
                            }
                        }
                        if !ap.is_whitelisted() {
                            ap.is_target = true;
                        }
                        return true;
                    }
                }
                Target::Ssid(tgt) => {
                    if tgt.target_match(ap) {
                        if !self.is_target_mac(&ap.mac_address) {
                            self.add(Target::Mac(TargetMAC {
                                addr: ap.mac_address,
                            }))
                        }
                        if !ap.is_whitelisted() {
                            ap.is_target = true;
                        }
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn get_targets(&mut self, ap: &mut AccessPoint) -> Vec<Target> {
        if self.empty() {
            return vec![];
        };
        let mut matches: Vec<Target> = Vec::new();

        for target in self.targets.clone() {
            match target {
                Target::Mac(ref tgt) => {
                    if tgt.target_match(ap) {
                        if let Some(ssid) = &ap.ssid {
                            if !self.is_target_ssid(ssid) {
                                self.add(Target::Ssid(TargetSSID {
                                    ssid: ssid.to_string(),
                                }));
                            }
                        }
                        if !ap.is_whitelisted() {
                            ap.is_target = true;
                        }
                        matches.push(target);
                    }
                }
                Target::Ssid(ref tgt) => {
                    if tgt.target_match(ap) {
                        if !self.is_target_mac(&ap.mac_address) {
                            self.add(Target::Mac(TargetMAC {
                                addr: ap.mac_address,
                            }))
                        }
                        if !ap.is_whitelisted() {
                            ap.is_target = true;
                        }
                        matches.push(target);
                    }
                }
            }
        }
        matches
    }

    pub fn is_actual_target_mac(&self, mac: &MacAddress) -> bool {
        for target in &self.targets {
            match target {
                Target::Mac(tgt) => {
                    if tgt.addr == *mac {
                        return true;
                    }
                }
                Target::Ssid(_) => {} // do nothing
            }
        }
        false
    }

    pub fn is_actual_target_ssid(&self, ssid: &str) -> bool {
        for target in &self.targets {
            match target {
                Target::Mac(_) => {} // do nothing, we don't have anything to compare to here.
                Target::Ssid(tgt) => {
                    if tgt.match_ssid(ssid.to_owned()) {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn is_target_mac(&self, mac: &MacAddress) -> bool {
        if self.empty() {
            return true;
        };

        for target in &self.targets {
            match target {
                Target::Mac(tgt) => {
                    if tgt.addr == *mac {
                        return true;
                    }
                }
                Target::Ssid(_) => {} // do nothing
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
                Target::Mac(_) => {} // do nothing, we don't have anything to compare to here.
                Target::Ssid(tgt) => {
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
                Target::Mac(_) => continue,
                Target::Ssid(_) => return true,
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
            if let Target::Ssid(tgt) = tgt {
                return Some(tgt.ssid.clone());
            }
        }
    }

    pub fn get_string(&self) -> String {
        self.targets
            .iter()
            .map(|target| match target {
                Target::Mac(mac_target) => format!("MAC: {}", mac_target.addr),
                Target::Ssid(ssid_target) => format!("SSID: {}", ssid_target.ssid),
            })
            .collect::<Vec<String>>()
            .join(", ")
    }

    pub fn get_ref(&self) -> &Vec<Target> {
        &self.targets
    }
}
