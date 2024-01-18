use std::time::SystemTime;

use libwifi::frame::{
    components::{
        DataHeader, FrameControl, MacAddress, ManagementHeader, RsnAkmSuite, RsnCipherSuite,
        RsnInformation, SequenceControl, StationInfo,
    },
    Ack, AssociationRequest, AssociationResponse, Authentication, Beacon, Cts, Data,
    Deauthentication, DeauthenticationReason, Disassociation, EapolKey, ProbeRequest,
    ProbeResponse, ReassociationRequest,
};

const RTH: [u8; 10] = [
    0x00, 0x00, /* radiotap version and padding */
    0x0a, 0x00, /* radiotap header length */
    0x00, 0x00, 0x00, 0x00, /* bitmap */
    0x20, 0x00, /* tx flags */
];

const RTH_NO_ACK: [u8; 10] = [
    0x00, 0x00, /* radiotap version and padding */
    0x0a, 0x00, /* radiotap header length */
    0x00, 0x80, 0x00, 0x00, /* bitmap */
    0x28, 0x00, /* tx flags */
];

// These frames are MOSTLY hard coded based on security research by Zer0Beat (HcxTools)
// There may be optimizations, changes in the future to how we can attack networks by manipulating these values for better results.
// These is a good platform for continued testing and optimization.

pub fn build_authentication_response(
    client: &MacAddress,
    ap_rogue: &MacAddress,
    bssid: &MacAddress,
    sequence: u16,
) -> Vec<u8> {
    let mut rth: Vec<u8> = RTH_NO_ACK.to_vec();

    let frame_control = FrameControl {
        protocol_version: 0,
        frame_type: libwifi::FrameType::Management,
        frame_subtype: libwifi::FrameSubType::Authentication,
        flags: 1u8,
    };

    let header: ManagementHeader = ManagementHeader {
        frame_control,
        duration: 15000u16.to_ne_bytes(),
        address_1: *client,
        address_2: *ap_rogue,
        address_3: *bssid,
        sequence_control: SequenceControl {
            fragment_number: 0u8,
            sequence_number: sequence,
        },
    };
    let authreq = Authentication {
        header,
        auth_algorithm: 0u16,
        auth_seq: 2u16,
        status_code: 0u16,
        challenge_text: None,
    };
    rth.extend(authreq.encode());
    rth
}

pub fn build_authentication_frame_noack(
    destination: &MacAddress,
    source_rogue: &MacAddress,
    sequence: u16,
) -> Vec<u8> {
    let mut rth: Vec<u8> = RTH_NO_ACK.to_vec();

    let frame_control = FrameControl {
        protocol_version: 0,
        frame_type: libwifi::FrameType::Management,
        frame_subtype: libwifi::FrameSubType::Authentication,
        flags: 1u8,
    };

    let header: ManagementHeader = ManagementHeader {
        frame_control,
        duration: 15000u16.to_ne_bytes(),
        address_1: *destination,
        address_2: *source_rogue,
        address_3: *destination,
        sequence_control: SequenceControl {
            fragment_number: 0u8,
            sequence_number: sequence,
        },
    };
    let authreq = Authentication {
        header,
        auth_algorithm: 0u16,
        auth_seq: 1u16,
        status_code: 0u16,
        challenge_text: None,
    };
    rth.extend(authreq.encode());
    rth
}

pub fn build_deauthentication_fm_ap(
    ap: &MacAddress,
    client: &MacAddress,
    sequence: u16,
    reason: DeauthenticationReason,
) -> Vec<u8> {
    let mut rth: Vec<u8> = RTH_NO_ACK.to_vec();

    let frame_control = FrameControl {
        protocol_version: 0,
        frame_type: libwifi::FrameType::Management,
        frame_subtype: libwifi::FrameSubType::Deauthentication,
        flags: 0u8,
    };

    let header: ManagementHeader = ManagementHeader {
        frame_control,
        duration: 15000u16.to_ne_bytes(),
        address_1: *client,
        address_2: *ap,
        address_3: *ap,
        sequence_control: SequenceControl {
            fragment_number: 0u8,
            sequence_number: sequence,
        },
    };
    let deauth = Deauthentication {
        header,
        reason_code: reason,
    };
    rth.extend(deauth.encode());
    rth
}

pub fn build_deauthentication_fm_client(
    ap: &MacAddress,
    client: &MacAddress,
    sequence: u16,
    reason: DeauthenticationReason,
) -> Vec<u8> {
    let mut rth: Vec<u8> = RTH_NO_ACK.to_vec();

    let frame_control = FrameControl {
        protocol_version: 0,
        frame_type: libwifi::FrameType::Management,
        frame_subtype: libwifi::FrameSubType::Deauthentication,
        flags: 1u8,
    };

    let header: ManagementHeader = ManagementHeader {
        frame_control,
        duration: 15000u16.to_ne_bytes(),
        address_1: *ap,
        address_2: *client,
        address_3: *ap,
        sequence_control: SequenceControl {
            fragment_number: 0u8,
            sequence_number: sequence,
        },
    };
    let authreq = Deauthentication {
        header,
        reason_code: reason,
    };
    rth.extend(authreq.encode());
    rth
}

pub fn build_association_request_rg(
    addr1: &MacAddress,
    addr_rogue: &MacAddress,
    addr3: &MacAddress,
    sequence: u16,
    ssid: Option<String>,
    group_cipher_suite: RsnCipherSuite,
    pairwise_cipher_suites: Vec<RsnCipherSuite>,
) -> Vec<u8> {
    let mut rth: Vec<u8> = RTH_NO_ACK.to_vec();

    let frame_control = FrameControl {
        protocol_version: 0,
        frame_type: libwifi::FrameType::Management,
        frame_subtype: libwifi::FrameSubType::AssociationRequest,
        flags: 1u8,
    };

    let header: ManagementHeader = ManagementHeader {
        frame_control,
        duration: [0x3a, 0x01],
        address_1: *addr1,
        address_2: *addr_rogue,
        address_3: *addr3,
        sequence_control: SequenceControl {
            fragment_number: 0u8,
            sequence_number: sequence,
        },
    };

    let frx = AssociationRequest {
        header,
        beacon_interval: 0x0005,
        capability_info: 0x0431,
        station_info: StationInfo {
            supported_rates: vec![1.0, 2.0, 5.5, 11.0, 6.0, 9.0, 12.0, 18.0],
            extended_supported_rates: Some(vec![24.0, 36.0, 48.0, 54.0]),
            ssid,
            ds_parameter_set: None,
            tim: None,
            country_info: None,
            power_constraint: None,
            ht_capabilities: None,
            vht_capabilities: None,
            rsn_information: Some(RsnInformation {
                version: 1,
                group_cipher_suite,
                pairwise_cipher_suites,
                akm_suites: vec![RsnAkmSuite::PSK],
                mfp_required: false,
                pre_auth: false,
                no_pairwise: false,
                ptksa_replay_counter: 0,
                gtksa_replay_counter: 0,
                mfp_capable: true,
                joint_multi_band_rsna: false,
                peerkey_enabled: false,
                extended_key_id: false,
                ocvc: false,
            }),
            wpa_info: None,
            vendor_specific: Vec::new(),
            data: vec![
                /* RM Enabled Capabilities */
                (0x46, vec![0x7b, 0x00, 0x02, 0x00, 0x00]),
                /* Supported Operating Classes */
                (0x3b, vec![0x51, 0x51, 0x53, 0x54]),
            ],
        },
    };
    rth.extend(frx.encode());
    rth
}

pub fn build_association_request(
    ap_mac: &MacAddress,
    client_mac: &MacAddress,
    ssid: Option<String>,
    sequence: u16,
    group_cipher_suite: RsnCipherSuite,
    pairwise_cipher_suites: Vec<RsnCipherSuite>,
) -> Vec<u8> {
    let mut rth: Vec<u8> = RTH_NO_ACK.to_vec();

    let frame_control = FrameControl {
        protocol_version: 0,
        frame_type: libwifi::FrameType::Management,
        frame_subtype: libwifi::FrameSubType::AssociationRequest,
        flags: 1u8,
    };

    let header: ManagementHeader = ManagementHeader {
        frame_control,
        duration: 15000u16.to_ne_bytes(),
        address_1: *ap_mac,
        address_2: *client_mac,
        address_3: *ap_mac,
        sequence_control: SequenceControl {
            fragment_number: 0u8,
            sequence_number: sequence,
        },
    };

    let frx = AssociationRequest {
        header,
        capability_info: 0x431,
        beacon_interval: 0x14,
        station_info: StationInfo {
            supported_rates: vec![1.0, 2.0, 5.5, 11.0, 6.0, 9.0, 12.0, 18.0],
            extended_supported_rates: Some(vec![24.0, 36.0, 48.0, 54.0]),
            ssid,
            ds_parameter_set: None,
            tim: None,
            country_info: None,
            power_constraint: None,
            ht_capabilities: None,
            vht_capabilities: None,
            rsn_information: Some(RsnInformation {
                version: 1,
                group_cipher_suite,
                pairwise_cipher_suites,
                akm_suites: vec![RsnAkmSuite::PSK],
                mfp_required: false,
                pre_auth: false,
                no_pairwise: false,
                ptksa_replay_counter: 0,
                gtksa_replay_counter: 0,
                mfp_capable: true,
                joint_multi_band_rsna: false,
                peerkey_enabled: false,
                extended_key_id: false,
                ocvc: false,
            }),
            wpa_info: None,
            vendor_specific: Vec::new(),
            data: vec![
                (0x46, vec![0x7b, 0x00, 0x02, 0x00, 0x00]),
                (0x3b, vec![0x51, 0x51, 0x53, 0x54]),
            ],
        },
    };
    rth.extend(frx.encode());
    rth
}

pub fn build_disassocation_from_client(
    ap_mac: &MacAddress,
    client_mac: &MacAddress,
    sequence: u16,
) -> Vec<u8> {
    let mut rth: Vec<u8> = RTH_NO_ACK.to_vec();

    let frame_control = FrameControl {
        protocol_version: 0,
        frame_type: libwifi::FrameType::Management,
        frame_subtype: libwifi::FrameSubType::Disassociation,
        flags: 1u8,
    };

    let header: ManagementHeader = ManagementHeader {
        frame_control,
        duration: 15000u16.to_ne_bytes(),
        address_1: *ap_mac,
        address_2: *client_mac,
        address_3: *ap_mac,
        sequence_control: SequenceControl {
            fragment_number: 0u8,
            sequence_number: sequence,
        },
    };

    let frx = Disassociation {
        header,
        reason_code: DeauthenticationReason::DisassociatedBecauseSTALeavingBSS,
    };
    rth.extend(frx.encode());
    rth
}

pub fn build_reassociation_request(
    ap_mac: &MacAddress,
    client_mac: &MacAddress,
    ssid: Option<String>,
    sequence: u16,
    group_cipher_suite: RsnCipherSuite,
    pairwise_cipher_suites: Vec<RsnCipherSuite>,
) -> Vec<u8> {
    let mut rth: Vec<u8> = RTH_NO_ACK.to_vec();

    let frame_control = FrameControl {
        protocol_version: 0,
        frame_type: libwifi::FrameType::Management,
        frame_subtype: libwifi::FrameSubType::ReassociationRequest,
        flags: 0u8,
    };

    let header: ManagementHeader = ManagementHeader {
        frame_control,
        duration: [0x01, 0x3a],
        address_1: *ap_mac,
        address_2: *client_mac,
        address_3: *ap_mac,
        sequence_control: SequenceControl {
            fragment_number: 0u8,
            sequence_number: sequence,
        },
    };

    let frx = ReassociationRequest {
        header,
        capability_info: 0x431,
        listen_interval: 0x14,
        current_ap_address: *ap_mac,
        station_info: StationInfo {
            supported_rates: vec![1.0, 2.0, 5.5, 11.0, 6.0, 9.0, 12.0, 18.0],
            extended_supported_rates: Some(vec![24.0, 36.0, 48.0, 54.0]),
            ssid,
            ds_parameter_set: None,
            tim: None,
            country_info: None,
            power_constraint: None,
            ht_capabilities: None,
            vht_capabilities: None,
            rsn_information: Some(RsnInformation {
                version: 1,
                group_cipher_suite,
                pairwise_cipher_suites,
                akm_suites: vec![RsnAkmSuite::PSK],
                mfp_required: false,
                pre_auth: false,
                no_pairwise: false,
                ptksa_replay_counter: 0,
                gtksa_replay_counter: 0,
                mfp_capable: true,
                joint_multi_band_rsna: false,
                peerkey_enabled: false,
                extended_key_id: false,
                ocvc: false,
            }),
            wpa_info: None,
            vendor_specific: Vec::new(),
            data: vec![
                (0x46, vec![0x7b, 0x00, 0x02, 0x00, 0x00]),
                (0x3b, vec![0x51, 0x51, 0x53, 0x54]),
            ],
        },
    };
    rth.extend(frx.encode());
    rth
}

pub fn build_probe_request_undirected(addr_rogue: &MacAddress, sequence: u16) -> Vec<u8> {
    let mut rth: Vec<u8> = RTH_NO_ACK.to_vec();

    let frame_control = FrameControl {
        protocol_version: 0,
        frame_type: libwifi::FrameType::Management,
        frame_subtype: libwifi::FrameSubType::ProbeRequest,
        flags: 0u8,
    };

    let header: ManagementHeader = ManagementHeader {
        frame_control,
        duration: [0x3a, 0x01],
        address_1: MacAddress([255, 255, 255, 255, 255, 255]),
        address_2: *addr_rogue,
        address_3: MacAddress([255, 255, 255, 255, 255, 255]),
        sequence_control: SequenceControl {
            fragment_number: 0u8,
            sequence_number: sequence,
        },
    };

    let frx = ProbeRequest {
        header,
        station_info: StationInfo {
            supported_rates: vec![1.0, 2.0, 5.5, 11.0, 6.0, 9.0, 12.0, 18.0],
            extended_supported_rates: Some(vec![24.0, 36.0, 48.0, 54.0]),
            ssid: None,
            ds_parameter_set: None,
            tim: None,
            country_info: None,
            power_constraint: None,
            ht_capabilities: None,
            vht_capabilities: None,
            rsn_information: None,
            wpa_info: None,
            vendor_specific: Vec::new(),
            data: Vec::new(),
        },
    };
    rth.extend(frx.encode());
    rth
}

pub fn build_probe_request_target(
    addr_rogue: &MacAddress,
    ap_addr: &MacAddress,
    sequence: u16,
) -> Vec<u8> {
    let mut rth: Vec<u8> = RTH_NO_ACK.to_vec();

    let frame_control = FrameControl {
        protocol_version: 0,
        frame_type: libwifi::FrameType::Management,
        frame_subtype: libwifi::FrameSubType::ProbeRequest,
        flags: 0u8,
    };

    let header: ManagementHeader = ManagementHeader {
        frame_control,
        duration: [0x3a, 0x01],
        address_1: *ap_addr,
        address_2: *addr_rogue,
        address_3: *ap_addr,
        sequence_control: SequenceControl {
            fragment_number: 0u8,
            sequence_number: sequence,
        },
    };

    let frx = ProbeRequest {
        header,
        station_info: StationInfo {
            supported_rates: vec![1.0, 2.0, 5.5, 11.0, 6.0, 9.0, 12.0, 18.0],
            extended_supported_rates: Some(vec![24.0, 36.0, 48.0, 54.0]),
            ssid: None,
            ds_parameter_set: None,
            tim: None,
            country_info: None,
            power_constraint: None,
            ht_capabilities: None,
            vht_capabilities: None,
            rsn_information: None,
            wpa_info: None,
            vendor_specific: Vec::new(),
            data: Vec::new(),
        },
    };
    rth.extend(frx.encode());
    rth
}

#[allow(dead_code)]
pub fn build_probe_request_directed(
    addr_rogue: &MacAddress,
    ssid: &String,
    sequence: u16,
) -> Vec<u8> {
    let mut rth: Vec<u8> = RTH_NO_ACK.to_vec();

    let frame_control = FrameControl {
        protocol_version: 0,
        frame_type: libwifi::FrameType::Management,
        frame_subtype: libwifi::FrameSubType::ProbeRequest,
        flags: 0u8,
    };

    let header: ManagementHeader = ManagementHeader {
        frame_control,
        duration: [0x3a, 0x01],
        address_1: MacAddress([255, 255, 255, 255, 255, 255]),
        address_2: *addr_rogue,
        address_3: MacAddress([255, 255, 255, 255, 255, 255]),
        sequence_control: SequenceControl {
            fragment_number: 0u8,
            sequence_number: sequence,
        },
    };

    let frx = ProbeRequest {
        header,
        station_info: StationInfo {
            supported_rates: vec![1.0, 2.0, 5.5, 11.0, 6.0, 9.0, 12.0, 18.0],
            extended_supported_rates: Some(vec![24.0, 36.0, 48.0, 54.0]),
            ssid: Some(ssid.to_string()),
            ds_parameter_set: None,
            tim: None,
            country_info: None,
            power_constraint: None,
            ht_capabilities: None,
            vht_capabilities: None,
            rsn_information: None,
            wpa_info: None,
            vendor_specific: Vec::new(),
            data: Vec::new(),
        },
    };
    rth.extend(frx.encode());
    rth
}

// Remember this is coming from an AP - this is a part of being rogue"
pub fn build_probe_response(
    addr_client: &MacAddress,
    addr_rogue_ap: &MacAddress,
    ssid: &String,
    sequence: u16,
    channel: u8,
) -> Vec<u8> {
    let mut rth: Vec<u8> = RTH_NO_ACK.to_vec();

    let frame_control = FrameControl {
        protocol_version: 0,
        frame_type: libwifi::FrameType::Management,
        frame_subtype: libwifi::FrameSubType::ProbeResponse,
        flags: 0u8,
    };

    let header: ManagementHeader = ManagementHeader {
        frame_control,
        duration: [0x3a, 0x01],
        address_1: *addr_client,
        address_2: *addr_rogue_ap,
        address_3: *addr_rogue_ap,
        sequence_control: SequenceControl {
            fragment_number: 0u8,
            sequence_number: sequence,
        },
    };

    let frx = ProbeResponse {
        header,
        station_info: StationInfo {
            supported_rates: vec![1.0, 2.0, 5.5, 11.0, 6.0, 9.0, 12.0, 18.0],
            extended_supported_rates: Some(vec![24.0, 36.0, 48.0, 54.0]),
            ssid: Some(ssid.to_string()),
            ds_parameter_set: Some(channel.try_into().unwrap()),
            tim: None,
            country_info: None,
            power_constraint: None,
            ht_capabilities: None,
            vht_capabilities: None,
            rsn_information: Some(RsnInformation {
                version: 1,
                group_cipher_suite: RsnCipherSuite::CCMP,
                pairwise_cipher_suites: vec![RsnCipherSuite::CCMP],
                akm_suites: vec![RsnAkmSuite::PSK],
                pre_auth: false,
                no_pairwise: false,
                ptksa_replay_counter: 0,
                gtksa_replay_counter: 0,
                mfp_required: false,
                mfp_capable: false,
                joint_multi_band_rsna: false,
                peerkey_enabled: false,
                extended_key_id: false,
                ocvc: false,
            }),
            wpa_info: None,
            vendor_specific: Vec::new(),
            data: Vec::new(),
        },
        timestamp: 1,
        beacon_interval: 1024,
        capability_info: 0x431,
    };
    rth.extend(frx.encode());
    rth
}

pub fn build_csa_beacon(beacon: Beacon, new_channel: u8) -> Vec<u8> {
    let mut rth: Vec<u8> = RTH_NO_ACK.to_vec();

    let mut frx = beacon.clone();
    frx.header.sequence_control.sequence_number =
        beacon.header.sequence_control.sequence_number + 1;
    frx.station_info
        .data
        .push((37u8, vec![0u8, new_channel, 3u8]));

    rth.extend(frx.encode());
    rth
}

// Remember this is coming from an AP - this is a part of being "rogue"
pub fn build_association_response(
    addr_client: &MacAddress,
    addr_rogue_ap: &MacAddress,
    bssid: &MacAddress,
    sequence: u16,
    ssid: &String,
) -> Vec<u8> {
    let mut rth: Vec<u8> = RTH_NO_ACK.to_vec();

    let frame_control = FrameControl {
        protocol_version: 0,
        frame_type: libwifi::FrameType::Management,
        frame_subtype: libwifi::FrameSubType::AssociationResponse,
        flags: 0u8,
    };

    let header: ManagementHeader = ManagementHeader {
        frame_control,
        duration: [0x3a, 0x01],
        address_1: *addr_client,
        address_2: *addr_rogue_ap,
        address_3: *bssid,
        sequence_control: SequenceControl {
            fragment_number: 0u8,
            sequence_number: sequence,
        },
    };

    let frx = AssociationResponse {
        header,
        capability_info: 0x431,
        status_code: 0,
        association_id: 49153u16,
        station_info: StationInfo {
            supported_rates: vec![1.0, 2.0, 5.5, 11.0, 6.0, 9.0, 12.0, 18.0],
            extended_supported_rates: Some(vec![24.0, 36.0, 48.0, 54.0]),
            ssid: Some(ssid.to_string()),
            ds_parameter_set: None,
            tim: None,
            country_info: None,
            power_constraint: None,
            ht_capabilities: None,
            vht_capabilities: None,
            rsn_information: None,
            wpa_info: None,
            vendor_specific: vec![],
            data: vec![],
        },
    };
    rth.extend(frx.encode());
    rth
}

pub fn build_eapol_m1(
    addr_client: &MacAddress,
    addr_rogue_ap: &MacAddress,
    bssid: &MacAddress,
    sequence: u16,
    rogue_m1: &EapolKey,
) -> Vec<u8> {
    let mut rth: Vec<u8> = RTH_NO_ACK.to_vec();

    let frame_control = FrameControl {
        protocol_version: 0,
        frame_type: libwifi::FrameType::Data,
        frame_subtype: libwifi::FrameSubType::Data,
        flags: 2u8,
    };

    let header: DataHeader = DataHeader {
        frame_control,
        duration: [0x3a, 0x01],
        address_1: *addr_client,
        address_2: *addr_rogue_ap,
        address_3: *bssid,
        sequence_control: SequenceControl {
            fragment_number: 0u8,
            sequence_number: sequence,
        },
        address_4: None,
        qos: None,
    };

    let mut rogue = rogue_m1.clone();
    rogue.timestamp = SystemTime::now();

    let frx = Data {
        header,
        eapol_key: Some(rogue),
        data: Vec::new(),
    };
    rth.extend(frx.encode());
    rth
}

pub fn build_ack(addr: &MacAddress) -> Vec<u8> {
    let mut rth: Vec<u8> = RTH_NO_ACK.to_vec();

    let frame_control = FrameControl {
        protocol_version: 0,
        frame_type: libwifi::FrameType::Control,
        frame_subtype: libwifi::FrameSubType::Ack,
        flags: 0u8,
    };

    let frx = Ack {
        frame_control,
        duration: [0x3a, 0x01],
        destination: *addr,
    };
    rth.extend(frx.encode());
    rth
}

pub fn build_cts(dest: &MacAddress) -> Vec<u8> {
    let mut rth: Vec<u8> = RTH_NO_ACK.to_vec();

    let frame_control = FrameControl {
        protocol_version: 0,
        frame_type: libwifi::FrameType::Control,
        frame_subtype: libwifi::FrameSubType::Cts,
        flags: 0u8,
    };

    let frx = Cts {
        frame_control,
        duration: [0x3a, 0x01],
        destination: *dest,
    };
    rth.extend(frx.encode());
    rth
}
