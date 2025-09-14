use std::time::SystemTime;

use crate::error::Error;
use crate::frame::components::FrameControl;
use crate::frame::*;
use crate::parsers::parse_data_header;
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u64, le_u8},
};

/// Parse a [Data] frame.
pub fn parse_data(frame_control: FrameControl, input: &[u8]) -> Result<Frame, Error> {
    let (remaining, header) = parse_data_header(frame_control, input)?;

    // Check for EAPOL LLC header
    let eapol_llc_header: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e];
    if remaining.starts_with(&eapol_llc_header) {
        let eapol_key = parse_eapol_key(&remaining[eapol_llc_header.len()..])?;
        Ok(Frame::Data(Data {
            header,
            eapol_key: Some(eapol_key),
            data: Vec::new(), // No other data if EAPOL-Key frame is present
        }))
    } else {
        Ok(Frame::Data(Data {
            header,
            eapol_key: None,
            data: remaining.to_vec(),
        }))
    }
}

/// Parse a [NullData] frame.
pub fn parse_null_data(frame_control: FrameControl, input: &[u8]) -> Result<Frame, Error> {
    let (_, header) = parse_data_header(frame_control, input)?;

    Ok(Frame::NullData(NullData { header }))
}

/// Parse a [QosData] frame.
pub fn parse_qos_data(frame_control: FrameControl, input: &[u8]) -> Result<Frame, Error> {
    let (remaining, header) = parse_data_header(frame_control, input)?;

    // Check for EAPOL LLC header
    let eapol_llc_header: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e];
    if remaining.starts_with(&eapol_llc_header) {
        let eapol_key = parse_eapol_key(&remaining[eapol_llc_header.len()..])?;
        Ok(Frame::QosData(QosData {
            header,
            eapol_key: Some(eapol_key),
            data: Vec::new(), // No other data if EAPOL-Key frame is present
        }))
    } else {
        Ok(Frame::QosData(QosData {
            header,
            eapol_key: None,
            data: remaining.to_vec(),
        }))
    }
}

/// Parse a [QosNull] frame.
pub fn parse_qos_null(frame_control: FrameControl, input: &[u8]) -> Result<Frame, Error> {
    let (_, header) = parse_data_header(frame_control, input)?;

    Ok(Frame::QosNull(QosNull { header }))
}

// DataCfAck
pub fn parse_data_cf_ack(frame_control: FrameControl, input: &[u8]) -> Result<Frame, Error> {
    let (remaining, header) = parse_data_header(frame_control, input)?;

    // Check for EAPOL LLC header
    let eapol_llc_header: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e];
    if remaining.starts_with(&eapol_llc_header) {
        let eapol_key = parse_eapol_key(&remaining[eapol_llc_header.len()..])?;
        Ok(Frame::DataCfAck(DataCfAck {
            header,
            eapol_key: Some(eapol_key),
            data: Vec::new(), // No other data if EAPOL-Key frame is present
        }))
    } else {
        Ok(Frame::DataCfAck(DataCfAck {
            header,
            eapol_key: None,
            data: remaining.to_vec(),
        }))
    }
}

// DataCfPoll
pub fn parse_data_cf_poll(frame_control: FrameControl, input: &[u8]) -> Result<Frame, Error> {
    let (remaining, header) = parse_data_header(frame_control, input)?;

    // Check for EAPOL LLC header
    let eapol_llc_header: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e];
    if remaining.starts_with(&eapol_llc_header) {
        let eapol_key = parse_eapol_key(&remaining[eapol_llc_header.len()..])?;
        Ok(Frame::DataCfPoll(DataCfPoll {
            header,
            eapol_key: Some(eapol_key),
            data: Vec::new(), // No other data if EAPOL-Key frame is present
        }))
    } else {
        Ok(Frame::DataCfPoll(DataCfPoll {
            header,
            eapol_key: None,
            data: remaining.to_vec(),
        }))
    }
}

// DataCfAckCfPoll
pub fn parse_data_cf_ack_cf_poll(
    frame_control: FrameControl,
    input: &[u8],
) -> Result<Frame, Error> {
    let (remaining, header) = parse_data_header(frame_control, input)?;

    // Check for EAPOL LLC header
    let eapol_llc_header: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e];
    if remaining.starts_with(&eapol_llc_header) {
        let eapol_key = parse_eapol_key(&remaining[eapol_llc_header.len()..])?;
        Ok(Frame::DataCfAckCfPoll(DataCfAckCfPoll {
            header,
            eapol_key: Some(eapol_key),
            data: Vec::new(), // No other data if EAPOL-Key frame is present
        }))
    } else {
        Ok(Frame::DataCfAckCfPoll(DataCfAckCfPoll {
            header,
            eapol_key: None,
            data: remaining.to_vec(),
        }))
    }
}

// CfAck
pub fn parse_cf_ack(frame_control: FrameControl, input: &[u8]) -> Result<Frame, Error> {
    let (_, header) = parse_data_header(frame_control, input)?;
    Ok(Frame::CfAck(CfAck { header }))
}

// CfPoll
pub fn parse_cf_poll(frame_control: FrameControl, input: &[u8]) -> Result<Frame, Error> {
    let (_, header) = parse_data_header(frame_control, input)?;
    Ok(Frame::CfPoll(CfPoll { header }))
}

// CfAckCfPoll
pub fn parse_cf_ack_cf_poll(frame_control: FrameControl, input: &[u8]) -> Result<Frame, Error> {
    let (_, header) = parse_data_header(frame_control, input)?;
    Ok(Frame::CfAckCfPoll(CfAckCfPoll { header }))
}

// QosDataCfAck
pub fn parse_qos_data_cf_ack(frame_control: FrameControl, input: &[u8]) -> Result<Frame, Error> {
    let (remaining, header) = parse_data_header(frame_control, input)?;

    // Check for EAPOL LLC header
    let eapol_llc_header: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e];
    if remaining.starts_with(&eapol_llc_header) {
        let eapol_key = parse_eapol_key(&remaining[eapol_llc_header.len()..])?;
        Ok(Frame::QosDataCfAck(QosDataCfAck {
            header,
            eapol_key: Some(eapol_key),
            data: Vec::new(), // No other data if EAPOL-Key frame is present
        }))
    } else {
        Ok(Frame::QosDataCfAck(QosDataCfAck {
            header,
            eapol_key: None,
            data: remaining.to_vec(),
        }))
    }
}

// QosDataCfPoll
pub fn parse_qos_data_cf_poll(frame_control: FrameControl, input: &[u8]) -> Result<Frame, Error> {
    let (remaining, header) = parse_data_header(frame_control, input)?;

    // Check for EAPOL LLC header
    let eapol_llc_header: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e];
    if remaining.starts_with(&eapol_llc_header) {
        let eapol_key = parse_eapol_key(&remaining[eapol_llc_header.len()..])?;
        Ok(Frame::QosDataCfPoll(QosDataCfPoll {
            header,
            eapol_key: Some(eapol_key),
            data: Vec::new(), // No other data if EAPOL-Key frame is present
        }))
    } else {
        Ok(Frame::QosDataCfPoll(QosDataCfPoll {
            header,
            eapol_key: None,
            data: remaining.to_vec(),
        }))
    }
}

// QosDataCfAckCfPoll
pub fn parse_qos_data_cf_ack_cf_poll(
    frame_control: FrameControl,
    input: &[u8],
) -> Result<Frame, Error> {
    let (remaining, header) = parse_data_header(frame_control, input)?;

    // Check for EAPOL LLC header
    let eapol_llc_header: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e];
    if remaining.starts_with(&eapol_llc_header) {
        let eapol_key = parse_eapol_key(&remaining[eapol_llc_header.len()..])?;
        Ok(Frame::QosDataCfAckCfPoll(QosDataCfAckCfPoll {
            header,
            eapol_key: Some(eapol_key),
            data: Vec::new(), // No other data if EAPOL-Key frame is present
        }))
    } else {
        Ok(Frame::QosDataCfAckCfPoll(QosDataCfAckCfPoll {
            header,
            eapol_key: None,
            data: remaining.to_vec(),
        }))
    }
}

// QosCfPoll
pub fn parse_qos_cf_poll(frame_control: FrameControl, input: &[u8]) -> Result<Frame, Error> {
    let (_, header) = parse_data_header(frame_control, input)?;
    Ok(Frame::QosCfPoll(QosCfPoll { header }))
}

// QosCfAckCfPoll
pub fn parse_qos_cf_ack_cf_poll(frame_control: FrameControl, input: &[u8]) -> Result<Frame, Error> {
    let (_, header) = parse_data_header(frame_control, input)?;
    Ok(Frame::QosCfAckCfPoll(QosCfAckCfPoll { header }))
}

/// Parse a [EapolKey] Frame
pub fn parse_eapol_key(input: &[u8]) -> Result<EapolKey, Error> {
    let (input, protocol_version) = le_u8(input)?;
    let (input, packet_type) = le_u8(input)?;
    let (input, packet_length) = be_u16(input)?;
    let (input, descriptor_type) = le_u8(input)?;
    let (input, key_information) = be_u16(input)?;
    let (input, key_length) = be_u16(input)?;
    let (input, replay_counter) = be_u64(input)?;
    let (input, key_nonce) = take(32usize)(input)?;
    let (input, key_iv) = take(16usize)(input)?;
    let (input, key_rsc) = be_u64(input)?;
    let (input, key_id) = be_u64(input)?;
    let (input, key_mic) = take(16usize)(input)?;
    let (input, key_data_length) = be_u16(input)?;
    let (_, key_data) = take(key_data_length as usize)(input)?;

    Ok(EapolKey {
        protocol_version,
        timestamp: SystemTime::now(),
        packet_type,
        packet_length,
        descriptor_type,
        key_information,
        key_length,
        replay_counter,
        key_nonce: key_nonce.try_into().expect("Slice with incorrect length"),
        key_iv: key_iv.try_into().expect("Slice with incorrect length"),
        key_rsc,
        key_id,
        key_mic: key_mic.try_into().expect("Slice with incorrect length"),
        key_data_length,
        key_data: key_data.to_vec(),
    })
}
