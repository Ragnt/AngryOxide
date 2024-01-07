#[derive(Clone, Debug, Default)]
/// StationInfo is used to parse and store variable length fields that are often sent
/// with management frames.
///
/// Each field has an `id`, the length of the bytes for this field, and then payload of the field.
/// Since there's a large number of possible fields and many propriatary vendor-specific usages
/// of these fields, this generic solution is used to capture all of them.
///
/// It is also important to note that most of these fields won't be sent most of the time. \
/// All fields that are already handled by this library get their own field in the StationInfo
/// struct.
///
/// Since we cannot handle all all those elements, the bytes of all unhandled elements will
/// be saved in the `data` field under the respectiv element id.

pub struct StationInfo {
    pub supported_rates: Vec<f32>,
    pub extended_supported_rates: Option<Vec<f32>>,
    pub ssid: Option<String>,
    pub ds_parameter_set: Option<u8>,
    pub tim: Option<Vec<u8>>,
    pub country_info: Option<Vec<u8>>,
    pub power_constraint: Option<u8>,
    pub ht_capabilities: Option<Vec<u8>>,
    pub vht_capabilities: Option<Vec<u8>>,
    pub rsn_information: Option<RsnInformation>,
    pub wpa_info: Option<WpaInformation>,
    pub vendor_specific: Vec<VendorSpecificInfo>,
    pub data: Vec<(u8, Vec<u8>)>,
}

impl StationInfo {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        if !self.supported_rates.is_empty() {
            // Encode Supported Rates
            bytes.push(1); // ID
            bytes.push(self.supported_rates.len() as u8);
            for &rate_mbps in &self.supported_rates {
                // Convert rate from Mbps to 500 kbps units and then to a byte
                let rate_byte = (rate_mbps * 2.0) as u8;
                let rate_byte_with_flag = rate_byte | 0x80; // Setting MSB
                bytes.push(rate_byte_with_flag);
            }
        }

        if let Some(ext_rates) = &self.extended_supported_rates {
            // Encode Supported Rates
            bytes.push(50); // ID
            bytes.push(ext_rates.len() as u8);
            for &rate_mbps in ext_rates {
                // Convert rate from Mbps to 500 kbps units and then to a byte
                let rate_byte = (rate_mbps * 2.0) as u8;
                let rate_byte_with_flag = rate_byte | 0x80; // Setting MSB
                bytes.push(rate_byte_with_flag);
            }
        }

        // Encode SSID (if present)
        if let Some(ssid) = &self.ssid {
            bytes.push(0); // ID
            bytes.push(ssid.len() as u8); // Length of SSID
            bytes.extend_from_slice(ssid.as_bytes()); // SSID as bytes
        } else {
            bytes.push(0);
            bytes.push(0);
        }

        // Encode DS Parameter Set (if present)
        if let Some(ds_param) = self.ds_parameter_set {
            bytes.push(3); // DS Parameter Set tag number
            bytes.push(1); // Length is always 1 byte
            bytes.push(ds_param);
        }

        // Encode TIM (if present) - Tag Number: 5
        if let Some(tim) = &self.tim {
            bytes.push(5); // TIM tag number
            bytes.push(tim.len() as u8); // Length of TIM
            bytes.extend(tim);
        }

        // Encode Country Info (if present) - Tag Number: 7
        if let Some(country_info) = &self.country_info {
            bytes.push(7); // Country Info tag number
            bytes.push(country_info.len() as u8); // Length of Country Info
            bytes.extend(country_info);
        }

        // Encode Power Constraint (if present) - Tag Number: 32
        if let Some(power_constraint) = self.power_constraint {
            bytes.push(32); // Power Constraint tag number
            bytes.push(1); // Length is always 1 byte
            bytes.push(power_constraint);
        }

        // Encode HT Capabilities (if present) - Tag Number: 45
        if let Some(ht_capabilities) = &self.ht_capabilities {
            bytes.push(45); // HT Capabilities tag number
            bytes.push(ht_capabilities.len() as u8); // Length of HT Capabilities
            bytes.extend(ht_capabilities);
        }

        // Encode VHT Capabilities (if present) - Tag Number: 191
        if let Some(vht_capabilities) = &self.vht_capabilities {
            bytes.push(191); // VHT Capabilities tag number
            bytes.push(vht_capabilities.len() as u8); // Length of VHT Capabilities
            bytes.extend(vht_capabilities);
        }

        // Encode RSN Information (if present) - Tag Number: 48
        if let Some(rsn_info) = &self.rsn_information {
            bytes.push(48); // RSN Information tag number
            let rsn_encoded = rsn_info.encode();
            bytes.push(rsn_encoded.len() as u8); // Length of RSN Information
            bytes.extend(rsn_encoded);
        }

        // Encode WPA Information (if present) - This is usually vendor-specific
        // WPA Information uses the vendor-specific tag number (221) with the specific OUI for WPA
        if let Some(wpa_info) = &self.wpa_info {
            bytes.push(221); // Vendor-Specific tag number
            let wpa_encoded = wpa_info.encode();
            bytes.push(wpa_encoded.len() as u8); // Length of WPA Information
            bytes.extend(wpa_encoded);
        }

        // Encode Vendor Specific Info
        for vendor_info in &self.vendor_specific {
            bytes.push(vendor_info.element_id);
            bytes.push(vendor_info.length);
            bytes.extend_from_slice(&vendor_info.oui);
            bytes.push(vendor_info.oui_type);
            bytes.extend(&vendor_info.data);
        }

        // Encode additional data
        for (id, data) in &self.data {
            bytes.push(*id);
            bytes.push(data.len() as u8);
            bytes.extend(data);
        }

        bytes
    }
}

#[derive(Clone, Debug, Default)]
pub struct VendorSpecificInfo {
    pub element_id: u8,
    pub length: u8,
    pub oui: [u8; 3],
    pub oui_type: u8,
    pub data: Vec<u8>,
}

impl VendorSpecificInfo {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.push(self.element_id);
        bytes.push(self.length);
        bytes.extend_from_slice(&self.oui);
        bytes.push(self.oui_type);
        bytes.extend(&self.data);

        bytes
    }
}

#[derive(Clone, Debug, Default)]
pub struct WpaInformation {
    pub version: u16,
    pub multicast_cipher_suite: WpaCipherSuite,
    pub unicast_cipher_suites: Vec<WpaCipherSuite>,
    pub akm_suites: Vec<WpaAkmSuite>,
}

impl WpaInformation {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Encode version
        bytes.extend_from_slice(&self.version.to_le_bytes());

        // Encode Multicast Cipher Suite
        bytes.extend(self.multicast_cipher_suite.encode());

        // Encode Unicast Cipher Suites
        bytes.extend_from_slice(&(self.unicast_cipher_suites.len() as u16).to_le_bytes());
        for suite in &self.unicast_cipher_suites {
            bytes.extend(suite.encode());
        }

        // Encode AKM Suites
        bytes.extend_from_slice(&(self.akm_suites.len() as u16).to_le_bytes());
        for suite in &self.akm_suites {
            bytes.extend(suite.encode());
        }

        bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum WpaCipherSuite {
    Wep40,
    Wep104,
    Tkip,
    #[default]
    Ccmp,
    Unknown(Vec<u8>),
}

impl WpaCipherSuite {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            WpaCipherSuite::Wep40 => vec![0x00, 0x50, 0xF2, 0x01],
            WpaCipherSuite::Wep104 => vec![0x00, 0x50, 0xF2, 0x05],
            WpaCipherSuite::Tkip => vec![0x00, 0x50, 0xF2, 0x02],
            WpaCipherSuite::Ccmp => vec![0x00, 0x50, 0xF2, 0x04],
            WpaCipherSuite::Unknown(data) => data.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum WpaAkmSuite {
    #[default]
    Psk, // Typically represented as 00-50-F2-1
    Eap,              // Typically represented as 00-50-F2-2
    Unknown(Vec<u8>), // For any unrecognized AKM suites
}

impl WpaAkmSuite {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            WpaAkmSuite::Psk => vec![0x00, 0x50, 0xF2, 0x01],
            WpaAkmSuite::Eap => vec![0x00, 0x50, 0xF2, 0x02],
            WpaAkmSuite::Unknown(data) => data.clone(),
        }
    }
}

// Define the RsnInformation struct to hold the parsed data
#[derive(Clone, Debug, Default)]
pub struct RsnInformation {
    pub version: u16,
    pub group_cipher_suite: RsnCipherSuite,
    pub pairwise_cipher_suites: Vec<RsnCipherSuite>,
    pub akm_suites: Vec<RsnAkmSuite>,
    // RSN Capabilities Flags
    pub pre_auth: bool,
    pub no_pairwise: bool,
    pub ptksa_replay_counter: u8,
    pub gtksa_replay_counter: u8,
    pub mfp_required: bool,
    pub mfp_capable: bool,
    pub joint_multi_band_rsna: bool,
    pub peerkey_enabled: bool,
    pub extended_key_id: bool,
    pub ocvc: bool,
}

impl RsnInformation {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Encode version
        bytes.extend_from_slice(&self.version.to_le_bytes());

        // Encode Group Cipher Suite
        bytes.extend(self.group_cipher_suite.encode());

        // Encode Pairwise Cipher Suites
        bytes.extend_from_slice(&(self.pairwise_cipher_suites.len() as u16).to_le_bytes());
        for suite in &self.pairwise_cipher_suites {
            bytes.extend(suite.encode());
        }

        // Encode AKM Suites
        bytes.extend_from_slice(&(self.akm_suites.len() as u16).to_le_bytes());
        for suite in &self.akm_suites {
            bytes.extend(suite.encode());
        }

        // Encode RSN Capabilities
        let mut rsn_capabilities: u16 = 0;
        rsn_capabilities |= self.pre_auth as u16;
        rsn_capabilities |= (self.no_pairwise as u16) << 1;
        rsn_capabilities |= ((self.ptksa_replay_counter & 0x03) as u16) << 2;
        rsn_capabilities |= ((self.gtksa_replay_counter & 0x03) as u16) << 3;
        rsn_capabilities |= (self.mfp_required as u16) << 6;
        rsn_capabilities |= (self.mfp_capable as u16) << 7;
        rsn_capabilities |= (self.joint_multi_band_rsna as u16) << 8;
        rsn_capabilities |= (self.peerkey_enabled as u16) << 9;
        rsn_capabilities |= (self.extended_key_id as u16) << 13;
        rsn_capabilities |= (self.ocvc as u16) << 14;

        bytes.extend_from_slice(&rsn_capabilities.to_le_bytes());

        bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum RsnAkmSuite {
    #[default]
    PSK,
    EAP,
    PSKFT,
    EAPFT,
    SAE,
    SUITEBEAP256,
    PSK256,
    EAP256,
    Unknown(Vec<u8>),
}

impl RsnAkmSuite {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            RsnAkmSuite::EAP => vec![0x00, 0x0F, 0xAC, 0x01],
            RsnAkmSuite::PSK => vec![0x00, 0x0F, 0xAC, 0x02],
            RsnAkmSuite::EAPFT => vec![0x00, 0x0F, 0xAC, 0x03],
            RsnAkmSuite::PSKFT => vec![0x00, 0x0F, 0xAC, 0x04],
            RsnAkmSuite::EAP256 => vec![0x00, 0x0F, 0xAC, 0x05],
            RsnAkmSuite::PSK256 => vec![0x00, 0x0F, 0xAC, 0x06],
            RsnAkmSuite::SAE => vec![0x00, 0x0F, 0xAC, 0x08],
            RsnAkmSuite::SUITEBEAP256 => vec![0x00, 0x0F, 0xAC, 0x0b],
            RsnAkmSuite::Unknown(data) => data.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum RsnCipherSuite {
    None,
    WEP,
    TKIP,
    WRAP,
    #[default]
    CCMP,
    WEP104,
    Unknown(Vec<u8>),
}

impl RsnCipherSuite {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            RsnCipherSuite::None => vec![0x00, 0x0F, 0xAC, 0x00],
            RsnCipherSuite::WEP => vec![0x00, 0x0F, 0xAC, 0x01],
            RsnCipherSuite::TKIP => vec![0x00, 0x0F, 0xAC, 0x02],
            RsnCipherSuite::WRAP => vec![0x00, 0x0F, 0xAC, 0x03],
            RsnCipherSuite::CCMP => vec![0x00, 0x0F, 0xAC, 0x04],
            RsnCipherSuite::WEP104 => vec![0x00, 0x0F, 0xAC, 0x05],
            RsnCipherSuite::Unknown(data) => data.clone(),
        }
    }
}
