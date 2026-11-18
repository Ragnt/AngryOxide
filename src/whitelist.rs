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

/// Does a whitelist SSID entry match this SSID? Entries are glob patterns; an
/// entry that isn't a valid pattern (an SSID with an unclosed `[`, say)
/// matches only that exact SSID.
fn ssid_entry_matches(entry: &str, ssid: &str) -> bool {
    match Glob::new(entry) {
        Ok(glob) => glob.compile_matcher().is_match(ssid),
        Err(_) => entry == ssid,
    }
}

impl IsWhitelisted for WhiteSSID {
    fn whitelist_match(&self, ap: &AccessPoint) -> bool {
        if let Some(ssid) = &ap.ssid {
            return ssid_entry_matches(&self.ssid, ssid);
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
    MAC(WhiteMAC),
    SSID(WhiteSSID),
}

impl White {
    pub fn get_string(&self) -> String {
        match self {
            White::MAC(tgt) => tgt.addr.to_string(),
            White::SSID(tgt) => tgt.ssid.clone(),
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
                White::MAC(tgt) => {
                    if tgt.whitelist_match(ap) {
                        if let Some(ssid) = &ap.ssid {
                            if !self.is_whitelisted_ssid(ssid) {
                                self.add(White::SSID(WhiteSSID {
                                    ssid: ssid.to_string(),
                                }));
                            }
                        }
                        if ! ap.is_target() {
                            ap.is_whitelisted = true;
                        }
                        return true;
                    }
                }
                White::SSID(tgt) => {
                    if tgt.whitelist_match(ap) {
                        if !self.is_whitelisted_mac(&ap.mac_address) {
                            self.add(White::MAC(WhiteMAC {
                                addr: ap.mac_address,
                            }))
                        }
                        if ! ap.is_target() {
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
                White::MAC(ref tgt) => {
                    if tgt.whitelist_match(ap) {
                        if let Some(ssid) = &ap.ssid {
                            if !self.is_whitelisted_ssid(ssid) {
                                self.add(White::SSID(WhiteSSID {
                                    ssid: ssid.to_string(),
                                }));
                            }
                        }
                        if ! ap.is_target() {
                            ap.is_whitelisted = true;
                        }
                        matches.push(target);
                    }
                }
                White::SSID(ref tgt) => {
                    if tgt.whitelist_match(ap) {
                        if !self.is_whitelisted_mac(&ap.mac_address) {
                            self.add(White::MAC(WhiteMAC {
                                addr: ap.mac_address,
                            }))
                        }
                        if ! ap.is_target() {
                            ap.is_whitelisted = true;
                        }
                        matches.push(target);
                    }
                }
            }
        }
        matches
    }

    /// True when an SSID entry matches `ssid`, whether or not an AP with that
    /// SSID has been seen. Check this before answering for an SSID (the rogue
    /// M2 attack), when the real AP may not be in the access point list. An
    /// entry given as a MAC counts once its AP has been seen, which adds the
    /// AP's SSID to the list.
    pub fn matches_ssid(&self, ssid: &str) -> bool {
        self.devices.iter().any(|device| match device {
            White::SSID(tgt) => ssid_entry_matches(&tgt.ssid, ssid),
            White::MAC(_) => false,
        })
    }

    pub fn is_whitelisted_mac(&self, mac: &MacAddress) -> bool {
        if self.empty() {
            return true;
        };

        for target in &self.devices {
            match target {
                White::MAC(tgt) => {
                    if tgt.addr == *mac {
                        return true;
                    }
                }
                White::SSID(_) => {} // do nothing
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
                White::MAC(_) => {} // do nothing, we don't have anything to compare to here.
                White::SSID(tgt) => {
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
                White::MAC(_) => continue,
                White::SSID(_) => return true,
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
            if let White::SSID(tgt) = tgt {
                return Some(tgt.ssid.clone());
            }
        }
    }

    pub fn get_string(&self) -> String {
        self.devices
            .iter()
            .map(|target| match target {
                White::MAC(mac_target) => format!("MAC: {}", mac_target.addr),
                White::SSID(ssid_target) => format!("SSID: {}", ssid_target.ssid),
            })
            .collect::<Vec<String>>()
            .join(", ")
    }

    pub fn get_ref(&self) -> &Vec<White> {
        &self.devices
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn ap_with_ssid(ssid: &str) -> AccessPoint {
        let mut ap = AccessPoint::default();
        ap.ssid = Some(ssid.to_owned());
        ap
    }

    #[test]
    fn ssid_entries_are_glob_patterns() {
        assert!(WhiteSSID::new("My Network").whitelist_match(&ap_with_ssid("My Network")));
        assert!(WhiteSSID::new("Cafe*").whitelist_match(&ap_with_ssid("Cafe Guest")));
        assert!(!WhiteSSID::new("My Network").whitelist_match(&ap_with_ssid("Library WiFi")));
    }

    #[test]
    fn an_entry_that_is_not_a_pattern_matches_itself() {
        // Not a valid glob: Glob::new(...).unwrap() used to panic on it.
        assert!(Glob::new("Cafe [Guest").is_err());
        let entry = WhiteSSID::new("Cafe [Guest");
        assert!(entry.whitelist_match(&ap_with_ssid("Cafe [Guest")));
        assert!(!entry.whitelist_match(&ap_with_ssid("Cafe Guest")));
    }

    #[test]
    fn matches_ssid_needs_no_ap() {
        let list = WhiteList::from_vec(vec![
            White::SSID(WhiteSSID::new("My Network")),
            White::SSID(WhiteSSID::new("Cafe*")),
        ]);
        assert!(list.matches_ssid("My Network"));
        assert!(list.matches_ssid("Cafe Guest"));
        assert!(!list.matches_ssid("Library WiFi"));
    }

    #[test]
    fn an_empty_whitelist_matches_no_ssid() {
        assert!(!WhiteList::new().matches_ssid("My Network"));
    }

    #[test]
    fn a_mac_entry_matches_its_ssid_once_its_ap_is_seen() {
        let mac = MacAddress::from_str("00:00:5E:00:53:01").unwrap();
        let mut list = WhiteList::from_vec(vec![White::MAC(WhiteMAC::new(mac))]);
        assert!(!list.matches_ssid("My Network"));

        let mut ap = ap_with_ssid("My Network");
        ap.mac_address = mac;
        assert!(list.is_whitelisted(&mut ap));
        assert!(list.matches_ssid("My Network"));
    }
}
