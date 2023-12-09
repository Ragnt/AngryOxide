use nom::bytes::complete::take;
use nom::number::complete::u8 as get_u8;
use nom::sequence::tuple;
use nom::IResult;

use crate::frame::components::{
    RsnAkmSuite, RsnCipherSuite, RsnInformation, StationInfo, VendorSpecificInfo, WpaAkmSuite,
    WpaCipherSuite, WpaInformation,
};

/// Parse variable length and variable field information.
/// The general structure of the data looks like this:
///
/// 1 byte: Element id
/// 1 byte: Element length (up to 255 bytes)
/// $element_length bytes: Element data
///
/// This format is only used in management frames.
///
/// There might be multiple elements with the same element id,
/// which is why StationInfo uses a Vec instead of BTreeMap as a data structure.
pub fn parse_station_info(mut input: &[u8]) -> IResult<&[u8], StationInfo> {
    let mut station_info = StationInfo::default();

    let mut element_id;
    let mut length;
    let mut data;
    loop {
        (input, (element_id, length)) = tuple((get_u8, get_u8))(input)?;
        (input, data) = take(length)(input)?;
        if !data.is_empty() {
            match element_id {
                0 => {
                    let mut ssid = String::from_utf8_lossy(data).to_string();
                    if length == 0 {
                        ssid = "".to_string();
                    }
                    station_info.ssid = Some(ssid);
                }
                1 => station_info.supported_rates = parse_supported_rates(data),
                3 => station_info.ds_parameter_set = Some(data[0]),
                5 => station_info.tim = Some(data.to_vec()),
                7 => station_info.country_info = Some(data.to_vec()),
                32 => station_info.power_constraint = Some(data[0]),
                45 => station_info.ht_capabilities = Some(data.to_vec()),
                48 => {
                    if let Ok(rsn_info) = parse_rsn_information(data) {
                        station_info.rsn_information = Some(rsn_info)
                    }
                }
                50 => station_info.extended_supported_rates = Some(parse_supported_rates(data)),
                191 => station_info.vht_capabilities = Some(data.to_vec()),
                221 => {
                    // Vendor-specific tag
                    if data.len() >= 4 {
                        // Minimum length for OUI and OUI Type
                        let oui = [data[0], data[1], data[2]];
                        let oui_type = data[3];
                        let vendor_data = data[4..].to_vec();

                        if oui == [0x00, 0x50, 0xf2] && oui_type == 1 {
                            // Specific parsing for WPA Information Element
                            station_info.wpa_info =
                                Some(parse_wpa_information(&vendor_data).unwrap());
                        }

                        let vendor_specific_info = VendorSpecificInfo {
                            element_id,
                            length,
                            oui,
                            oui_type,
                            data: vendor_data,
                        };
                        station_info.vendor_specific.push(vendor_specific_info);
                    }
                }
                _ => {
                    station_info.data.push((element_id, data.to_vec()));
                }
            };

            if input.len() <= 4 {
                break;
            }
        }
    }

    Ok((input, station_info))
}

fn parse_wpa_information(data: &[u8]) -> Result<WpaInformation, &'static str> {
    if data.len() < 10 {
        return Err("WPA Information data too short");
    }

    let version = u16::from_le_bytes([data[0], data[1]]);
    if version != 1 {
        return Err("Unsupported WPA version");
    }

    let multicast_cipher_suite = parse_cipher_suite(&data[2..6]);
    let unicast_cipher_suite_count = u16::from_le_bytes([data[6], data[7]]) as usize;
    let mut offset = 8;

    if data.len() < offset + 4 * unicast_cipher_suite_count {
        return Err("WPA Information data too short for unicast cipher suites");
    }

    let mut unicast_cipher_suites = Vec::new();
    for _ in 0..unicast_cipher_suite_count {
        let cipher_suite = parse_cipher_suite(&data[offset..offset + 4]);
        unicast_cipher_suites.push(cipher_suite);
        offset += 4;
    }

    if data.len() < offset + 2 {
        return Err("WPA Information data too short for AKM suite count");
    }

    let akm_suite_count = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    if data.len() < offset + 4 * akm_suite_count {
        return Err("WPA Information data too short for AKM suites");
    }

    let mut akm_suites = Vec::new();
    for _ in 0..akm_suite_count {
        let akm_suite = parse_wpa_akm_suite(&data[offset..offset + 4]);
        akm_suites.push(akm_suite);
        offset += 4;
    }

    Ok(WpaInformation {
        version,
        multicast_cipher_suite,
        unicast_cipher_suites,
        akm_suites,
    })
}

fn parse_rsn_information(data: &[u8]) -> Result<RsnInformation, &'static str> {
    if data.len() < 10 {
        return Err("RSN Information data too short");
    }

    let version = u16::from_le_bytes([data[0], data[1]]);
    if version != 1 {
        return Err("Unsupported RSN version");
    }

    let group_cipher_suite = parse_group_cipher_suite(&data[2..6]);
    let pairwise_cipher_suite_count = u16::from_le_bytes([data[6], data[7]]) as usize;
    let mut offset = 8;

    let mut pairwise_cipher_suites = Vec::new();
    for _ in 0..pairwise_cipher_suite_count {
        let suite = parse_pairwise_cipher_suite(&data[offset..offset + 4]);
        pairwise_cipher_suites.push(suite);
        offset += 4;
    }

    let akm_suite_count = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    let mut akm_suites = Vec::new();
    for _ in 0..akm_suite_count {
        let suite = parse_akm_suite(&data[offset..offset + 4]);
        akm_suites.push(suite);
        offset += 4;
    }

    if data.len() >= offset + 2 {
        let rsn_capabilities = u16::from_le_bytes([data[offset], data[offset + 1]]);

        let pre_auth = (rsn_capabilities & (1 << 0)) != 0;
        let no_pairwise = (rsn_capabilities & (1 << 1)) != 0;
        let ptksa_replay_counter = ((rsn_capabilities >> 2) & 0x03) as u8; // Extract 2 bits starting at position 2
        let gtksa_replay_counter = ((rsn_capabilities >> 4) & 0x03) as u8; // Extract 2 bits starting at position 4
        let mfp_required = (rsn_capabilities & (1 << 6)) != 0;
        let mfp_capable = (rsn_capabilities & (1 << 7)) != 0;
        let joint_multi_band_rsna = (rsn_capabilities & (1 << 8)) != 0;
        let peerkey_enabled = (rsn_capabilities & (1 << 9)) != 0;
        let extended_key_id = (rsn_capabilities & (1 << 13)) != 0;
        let ocvc = (rsn_capabilities & (1 << 14)) != 0;

        Ok(RsnInformation {
            version,
            group_cipher_suite,
            pairwise_cipher_suites,
            akm_suites,
            pre_auth,
            no_pairwise,
            ptksa_replay_counter,
            gtksa_replay_counter,
            mfp_required,
            mfp_capable,
            joint_multi_band_rsna,
            peerkey_enabled,
            extended_key_id,
            ocvc,
        })
    } else {
        Err("RSN Information data too short for RSN Capabilities")
    }
}

fn parse_cipher_suite(data: &[u8]) -> WpaCipherSuite {
    match data {
        [0x00, 0x50, 0xF2, 0x01] => WpaCipherSuite::Wep40,
        [0x00, 0x50, 0xF2, 0x05] => WpaCipherSuite::Wep104,
        [0x00, 0x50, 0xF2, 0x02] => WpaCipherSuite::Tkip,
        [0x00, 0x50, 0xF2, 0x04] => WpaCipherSuite::Ccmp,
        _ => WpaCipherSuite::Unknown(data.to_vec()),
    }
}

fn parse_wpa_akm_suite(data: &[u8]) -> WpaAkmSuite {
    match data {
        [0x00, 0x50, 0xF2, 0x01] => WpaAkmSuite::Psk,
        [0x00, 0x50, 0xF2, 0x02] => WpaAkmSuite::Eap,
        _ => WpaAkmSuite::Unknown(data.to_vec()),
    }
}

/*
RsnCipherSuite::WEP => vec![0x00, 0x0F, 0xAC, 0x01],
RsnCipherSuite::TKIP => vec![0x00, 0x0F, 0xAC, 0x02],
RsnCipherSuite::WRAP => vec![0x00, 0x0F, 0xAC, 0x03],
RsnCipherSuite::CCMP => vec![0x00, 0x0F, 0xAC, 0x04],
RsnCipherSuite::WEP104 => vec![0x00, 0x0F, 0xAC, 0x05],
*/
fn parse_group_cipher_suite(data: &[u8]) -> RsnCipherSuite {
    match data {
        [0x00, 0x0F, 0xAC, 0x01] => RsnCipherSuite::WEP,
        [0x00, 0x0F, 0xAC, 0x05] => RsnCipherSuite::WEP104,
        [0x00, 0x0F, 0xAC, 0x02] => RsnCipherSuite::TKIP,
        [0x00, 0x0F, 0xAC, 0x04] => RsnCipherSuite::CCMP,
        [0x00, 0x0F, 0xAC, 0x03] => RsnCipherSuite::WRAP,
        _ => RsnCipherSuite::Unknown(data.to_vec()),
    }
}

fn parse_pairwise_cipher_suite(data: &[u8]) -> RsnCipherSuite {
    match data {
        [0x00, 0x0F, 0xAC, 0x00] => RsnCipherSuite::None,
        [0x00, 0x0F, 0xAC, 0x02] => RsnCipherSuite::TKIP,
        [0x00, 0x0F, 0xAC, 0x04] => RsnCipherSuite::CCMP,
        _ => RsnCipherSuite::Unknown(data.to_vec()),
    }
}

fn parse_akm_suite(data: &[u8]) -> RsnAkmSuite {
    match data {
        [0x00, 0x0F, 0xAC, 0x02] => RsnAkmSuite::PSK,
        [0x00, 0x0F, 0xAC, 0x01] => RsnAkmSuite::EAP,
        _ => RsnAkmSuite::Unknown(data.to_vec()),
    }
}

fn parse_supported_rates(input: &[u8]) -> Vec<f32> {
    input
        .iter()
        .map(|&rate| (rate & 0x7F) as f32 / 2.0) // Mask out the MSB and convert
        .collect()
}
