use crate::frame::components::DataHeader;
use crate::frame::components::{
    FrameControl, MacAddress, ManagementHeader, SequenceControl, StationInfo,
};
use crate::frame::management::{
    AssociationRequest, Authentication, Deauthentication, ProbeRequest,
};
use crate::frame::{EapolKey, QosData};
use std::error::Error;
use std::result::Result;

pub struct AssociationRequestBuilder {
    header: ManagementHeader,
    beacon_interval: u16,
    capability_info: u16,
    station_info: StationInfo,
}

impl AssociationRequestBuilder {
    pub fn new(header: ManagementHeader) -> Self {
        Self {
            header,
            beacon_interval: 100, // Default to 100 TU (Time Units)
            capability_info: 0,
            station_info: StationInfo::default(),
        }
    }

    pub fn beacon_interval(mut self, beacon_interval: u16) -> Self {
        self.beacon_interval = beacon_interval;
        self
    }

    pub fn capability_info(mut self, capability_info: u16) -> Self {
        self.capability_info = capability_info;
        self
    }

    pub fn station_info(mut self, station_info: StationInfo) -> Self {
        self.station_info = station_info;
        self
    }

    pub fn build(self) -> AssociationRequest {
        AssociationRequest {
            header: self.header,
            beacon_interval: self.beacon_interval,
            capability_info: self.capability_info,
            station_info: self.station_info,
        }
    }
}

pub struct AuthenticationBuilder {
    header: ManagementHeader,
    auth_algorithm: u16,
    auth_seq: u16,
    status_code: u16,
    challenge_text: Option<Vec<u8>>,
}

impl AuthenticationBuilder {
    pub fn new(header: ManagementHeader) -> Self {
        Self {
            header,
            auth_algorithm: 0, // Default to Open System
            auth_seq: 1,
            status_code: 0,
            challenge_text: None,
        }
    }

    pub fn auth_algorithm(mut self, auth_algorithm: u16) -> Self {
        self.auth_algorithm = auth_algorithm;
        self
    }

    pub fn auth_seq(mut self, auth_seq: u16) -> Self {
        self.auth_seq = auth_seq;
        self
    }

    pub fn status_code(mut self, status_code: u16) -> Self {
        self.status_code = status_code;
        self
    }

    pub fn challenge_text(mut self, challenge_text: Vec<u8>) -> Self {
        self.challenge_text = Some(challenge_text);
        self
    }

    pub fn build(self) -> Authentication {
        Authentication {
            header: self.header,
            auth_algorithm: self.auth_algorithm,
            auth_seq: self.auth_seq,
            status_code: self.status_code,
            challenge_text: self.challenge_text,
        }
    }
}

pub struct QosDataBuilder {
    header: DataHeader,
    eapol_key_builder: Option<EapolKeyBuilder>,
    data: Vec<u8>,
}

impl QosDataBuilder {
    pub fn new(header: DataHeader) -> Self {
        Self {
            header,
            eapol_key_builder: None,
            data: vec![],
        }
    }

    pub fn build(self) -> QosData {
        let eapol_key = self.eapol_key_builder.map(|builder| builder.build());
        QosData {
            header: self.header,
            eapol_key,
            data: self.data,
        }
    }

    pub fn with_eapol_key(mut self, builder: EapolKeyBuilder) -> Self {
        self.eapol_key_builder = Some(builder);
        self
    }

    pub fn data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }
}

pub struct EapolKeyBuilder {
    descriptor_type: u8,
    key_information: u16,
    key_length: u16,
    replay_counter: u64,
    key_nonce: [u8; 32],
    key_iv: [u8; 16],
    key_rsc: u64,
    key_id: u64,
    key_mic: [u8; 16],
    key_data_length: u16,
    key_data: Vec<u8>,
}

impl EapolKeyBuilder {
    pub fn new() -> Self {
        Self {
            descriptor_type: 0,
            key_information: 0,
            key_length: 0,
            replay_counter: 0,
            key_nonce: [0; 32],
            key_iv: [0; 16],
            key_rsc: 0,
            key_id: 0,
            key_mic: [0; 16],
            key_data_length: 0,
            key_data: vec![],
        }
    }

    pub fn build(self) -> EapolKey {
        EapolKey {
            descriptor_type: self.descriptor_type,
            key_information: self.key_information,
            key_length: self.key_length,
            replay_counter: self.replay_counter,
            key_nonce: self.key_nonce,
            key_iv: self.key_iv,
            key_rsc: self.key_rsc,
            key_id: self.key_id,
            key_mic: self.key_mic,
            key_data_length: self.key_data_length,
            key_data: self.key_data,
        }
    }

    pub fn descriptor_type(mut self, descriptor_type: u8) -> Self {
        self.descriptor_type = descriptor_type;
        self
    }

    pub fn key_information(mut self, key_information: u16) -> Self {
        self.key_information = key_information;
        self
    }

    pub fn key_length(mut self, key_length: u16) -> Self {
        self.key_length = key_length;
        self
    }

    pub fn replay_counter(mut self, replay_counter: u64) -> Self {
        self.replay_counter = replay_counter;
        self
    }

    pub fn key_nonce(mut self, key_nonce: [u8; 32]) -> Self {
        self.key_nonce = key_nonce;
        self
    }

    pub fn key_iv(mut self, key_iv: [u8; 16]) -> Self {
        self.key_iv = key_iv;
        self
    }

    pub fn key_rsc(mut self, key_rsc: u64) -> Self {
        self.key_rsc = key_rsc;
        self
    }

    pub fn key_id(mut self, key_id: u64) -> Self {
        self.key_id = key_id;
        self
    }

    pub fn key_mic(mut self, key_mic: [u8; 16]) -> Self {
        self.key_mic = key_mic;
        self
    }

    pub fn key_data_length(mut self, key_data_length: u16) -> Self {
        self.key_data_length = key_data_length;
        self
    }

    pub fn key_data(mut self, key_data: Vec<u8>) -> Self {
        self.key_data = key_data;
        self
    }
}

pub struct DeauthenticationFrameBuilder {
    frame_control: Option<FrameControl>,
    duration: Option<[u8; 2]>,
    address_1: Option<MacAddress>,
    address_2: Option<MacAddress>,
    address_3: Option<MacAddress>,
    sequence_control: Option<SequenceControl>,
    reason_code: Option<u16>,
}

impl DeauthenticationFrameBuilder {
    pub fn new() -> Self {
        DeauthenticationFrameBuilder {
            frame_control: None,
            duration: None,
            address_1: None,
            address_2: None,
            address_3: None,
            sequence_control: None,
            reason_code: None,
        }
    }

    pub fn source_addr(mut self, addr: [u8; 6]) -> Self {
        self.address_1 = Some(MacAddress(addr));
        self
    }

    pub fn dest_addr(mut self, addr: [u8; 6]) -> Self {
        self.address_2 = Some(MacAddress(addr));
        self
    }

    pub fn bssid(mut self, bssid: [u8; 6]) -> Self {
        self.address_3 = Some(MacAddress(bssid));
        self
    }

    pub fn reason_code(mut self, reason_code: u16) -> Self {
        self.reason_code = Some(reason_code);
        self
    }

    pub fn build(self) -> Result<Deauthentication, Box<dyn Error>> {
        let header = ManagementHeader {
            frame_control: self.frame_control.ok_or("Frame Control is required")?,
            duration: self.duration.ok_or("Duration is required")?,
            address_1: self.address_1.ok_or("Address 1 is required")?,
            address_2: self.address_2.ok_or("Address 2 is required")?,
            address_3: self.address_3.ok_or("Address 3 is required")?,
            sequence_control: self
                .sequence_control
                .ok_or("Sequence Control is required")?,
        };

        let reason_code = self.reason_code.ok_or("Reason code is required")?;

        Ok(Deauthentication {
            header,
            reason_code,
        })
    }
}

pub struct ProbeRequestBuilder {
    frame_control: Option<FrameControl>,
    duration: [u8; 2],
    address_1: Option<MacAddress>,
    address_2: Option<MacAddress>,
    address_3: Option<MacAddress>,
    sequence_control: Option<SequenceControl>,
    supported_rates: Vec<f32>,
    ssid: Option<String>,
    ds_parameter_set: Option<u8>,
    tim: Option<Vec<u8>>,
    country_info: Option<Vec<u8>>,
    power_constraint: Option<u8>,
    ht_capabilities: Option<Vec<u8>>,
    vht_capabilities: Option<Vec<u8>>,
    additional_data: Vec<(u8, Vec<u8>)>,
}

impl ProbeRequestBuilder {
    pub fn new() -> Self {
        Self {
            frame_control: None,     // or specify custom default values
            duration: [0; 2],        // assuming a zero duration as default
            address_1: None,         // or specify custom default values
            address_2: None,         // or specify custom default values
            address_3: None,         // or specify custom default values
            sequence_control: None,  // or specify custom default values
            supported_rates: vec![], // empty vector as default
            ssid: None,              // no SSID specified by default
            ds_parameter_set: None,  // no DS Parameter Set specified by default
            tim: None,               // no Traffic Indication Map specified by default
            country_info: None,      // no Country Information specified by default
            power_constraint: None,  // no Power Constraint specified by default
            ht_capabilities: None,   // no HT Capabilities specified by default
            vht_capabilities: None,  // no VHT Capabilities specified by default
            additional_data: vec![], // empty vector as default
        }
    }

    pub fn source_addr(mut self, addr: [u8; 6]) -> Self {
        self.address_1 = Some(MacAddress(addr));
        self
    }

    pub fn dest_addr(mut self, addr: [u8; 6]) -> Self {
        self.address_2 = Some(MacAddress(addr));
        self
    }

    pub fn bssid(mut self, bssid: [u8; 6]) -> Self {
        self.address_3 = Some(MacAddress(bssid));
        self
    }

    pub fn ssid(mut self, ssid: String) -> Self {
        self.ssid = Some(ssid);
        self
    }

    pub fn add_supported_rate(mut self, rate: f32) -> Self {
        self.supported_rates.push(rate);
        self
    }

    pub fn ds_parameter_set(mut self, ds_parameter_set: u8) -> Self {
        self.ds_parameter_set = Some(ds_parameter_set);
        self
    }

    pub fn tim(mut self, tim: Vec<u8>) -> Self {
        self.tim = Some(tim);
        self
    }

    pub fn country_info(mut self, country_info: Vec<u8>) -> Self {
        self.country_info = Some(country_info);
        self
    }

    pub fn power_constraint(mut self, power_constraint: u8) -> Self {
        self.power_constraint = Some(power_constraint);
        self
    }

    pub fn ht_capabilities(mut self, ht_capabilities: Vec<u8>) -> Self {
        self.ht_capabilities = Some(ht_capabilities);
        self
    }

    pub fn vht_capabilities(mut self, vht_capabilities: Vec<u8>) -> Self {
        self.vht_capabilities = Some(vht_capabilities);
        self
    }

    pub fn additional_data(mut self, element_id: u8, data: Vec<u8>) -> Self {
        self.additional_data.push((element_id, data));
        self
    }

    pub fn build(self) -> ProbeRequest {
        ProbeRequest {
            header: ManagementHeader {
                frame_control: self.frame_control.unwrap(),
                duration: self.duration,
                address_1: self.address_1.unwrap(),
                address_2: self.address_2.unwrap(),
                address_3: self.address_3.unwrap(),
                sequence_control: self.sequence_control.unwrap(),
            },
            station_info: StationInfo {
                supported_rates: self.supported_rates,
                ssid: self.ssid,
                ds_parameter_set: self.ds_parameter_set,
                tim: self.tim,
                country_info: self.country_info,
                power_constraint: self.power_constraint,
                ht_capabilities: self.ht_capabilities,
                vht_capabilities: self.vht_capabilities,
                data: self.additional_data,
            },
        }
    }
}
