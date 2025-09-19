use chrono::prelude::*;
use gpsd_proto::{get_data, handshake, ResponseData};
use std::io::{self, BufReader};
use std::net::TcpStream;

use std::time::{Duration, UNIX_EPOCH};
use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::SystemTime,
};

#[derive(Debug, Clone, PartialEq, Default)]
pub struct GpsData {
    pub lat: Option<f64>,          // Latitude
    pub lon: Option<f64>,          // Longitude
    pub alt: Option<f32>,          // Altitude MSL
    pub alt_g: Option<f32>,        // Altitude AGL
    pub eph: Option<f32>,          // Horizontal Position Error
    pub epv: Option<f32>,          // Vertical Position Error
    pub speed: Option<f32>,        // Speed
    pub heading: Option<f32>,      // Heading
    pub fix: Option<u8>,           // GPS Fix
    pub hdop: Option<f32>,         // Horizontal Dilution of Precision
    pub vdop: Option<f32>,         // Vertical Dilution of Precision
    pub timestamp: Option<String>, // Timestamp
}

impl GpsData {
    // Function to update data with non-option values
    pub fn update(&mut self, new_data: GpsData) {
        self.lat = new_data.lat.or(self.lat);
        self.lon = new_data.lon.or(self.lon);
        self.alt = new_data.alt.or(self.alt);
        self.alt_g = new_data.alt_g.or(self.alt_g);
        self.eph = new_data.eph.or(self.eph);
        self.epv = new_data.epv.or(self.epv);
        self.speed = new_data.speed.or(self.speed);
        self.heading = new_data.heading.or(self.heading);
        self.fix = new_data.fix.or(self.fix);
        self.hdop = new_data.hdop.or(self.hdop);
        self.vdop = new_data.vdop.or(self.vdop);
        self.timestamp = new_data.timestamp.or(self.timestamp.clone());
    }

    pub fn reset(&mut self) {
        self.lat = None;
        self.lon = None;
        self.alt = None;
        self.alt_g = None;
        self.eph = None;
        self.epv = None;
        self.speed = None;
        self.heading = None;
        self.fix = None;
        self.hdop = None;
        self.vdop = None;
        self.timestamp = None;
    }

    pub fn has_fix(&self) -> bool {
        if self.fix.is_some_and(|f| f > 0) {
            return true;
        }
        false
    }

    pub fn has_gpsd(&self) -> bool {
        if self.fix.is_some() {
            return true;
        }
        false
    }

    pub fn create_option_block(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![];
        let mut header: Vec<u8> = vec![];
        let mut data: Vec<u8> = vec![];

        header.extend_from_slice(&55922u32.to_ne_bytes());
        header.push(0x47); // Magic
        header.push(0x1); // GPS Version
        header.extend_from_slice(&[0, 0]); // Length Placeholder

        // GPS Presence Bitmask
        // GPS Fields Presence Bitmask
        let mut bitmask = 0u32;

        if self.lon.is_some() {
            bitmask |= 0x2;
        }
        if self.lat.is_some() {
            bitmask |= 0x4;
        }
        if self.alt.is_some() {
            bitmask |= 0x8;
        }
        if self.alt_g.is_some() {
            bitmask |= 0x10;
        }
        if self.eph.is_some() {
            bitmask |= 0x80;
        }
        if self.epv.is_some() {
            bitmask |= 0x100;
        }
        if self.timestamp.is_some() {
            bitmask |= 0x400;
        }
        if self.timestamp.is_some() {
            bitmask |= 0x800;
        }

        header.extend_from_slice(&bitmask.to_ne_bytes());

        // Add data

        // Lat
        if let Some(lat) = self.lat {
            data.extend_from_slice(&Fixed3_7::from_float(lat).unwrap().value.to_ne_bytes());
        }
        // Lon
        if let Some(lon) = self.lon {
            data.extend_from_slice(&Fixed3_7::from_float(lon).unwrap().value.to_ne_bytes());
        }
        // Alt
        if let Some(alt) = self.alt {
            data.extend_from_slice(&Fixed6_4::from_float(alt).unwrap().value.to_ne_bytes());
        }
        // Alt_G
        if let Some(alt_g) = self.alt_g {
            data.extend_from_slice(&Fixed6_4::from_float(alt_g).unwrap().value.to_ne_bytes());
        }
        // EPH
        if let Some(eph) = self.eph {
            data.extend_from_slice(&Fixed6_4::from_float(eph).unwrap().value.to_ne_bytes());
        }
        // EPV
        if let Some(epv) = self.epv {
            data.extend_from_slice(&Fixed6_4::from_float(epv).unwrap().value.to_ne_bytes());
        }
        // Timestamp High//Low
        if let Some(timestamp) = &self.timestamp {
            let high = Timestamp::from_iso8601(timestamp).unwrap_or_default().high;
            let low = Timestamp::from_iso8601(timestamp).unwrap_or_default().low;
            data.extend_from_slice(&high.to_ne_bytes());
            data.extend_from_slice(&low.to_ne_bytes());
        }

        // Update the length field (using data length WITHOUT padding)
        let length: u16 = data.len() as u16;
        header[6..8].copy_from_slice(&length.to_ne_bytes());

        // Padding data to 32 bits
        let next_multiple_of_4 = if data.len().is_multiple_of(4) {
            data.len() // if it's already a multiple of 4, no need to pad
        } else {
            (data.len() / 4 + 1) * 4 // next multiple of 4
        };

        // Pad the buffer with zeros up to the next multiple of 4 bytes (32 bits)
        while data.len() < next_multiple_of_4 {
            data.push(0);
        }

        buffer.extend_from_slice(&header);
        buffer.extend_from_slice(&data);

        buffer
    }
}

pub struct GPSDSource {
    handle: Option<thread::JoinHandle<()>>,
    pub alive: Arc<AtomicBool>,
    host: IpAddr,
    port: u16,
    latest: Arc<Mutex<GpsData>>,
}

impl GPSDSource {
    pub fn new(host: IpAddr, port: u16) -> GPSDSource {
        GPSDSource {
            handle: None,
            alive: Arc::new(AtomicBool::new(false)),
            host,
            port,
            latest: Arc::new(Mutex::new(GpsData::default())),
        }
    }

    pub fn get_gps(&mut self) -> GpsData {
        let gps_data_lock = self.latest.lock().unwrap();
        gps_data_lock.clone()
    }

    pub fn start(&mut self) {
        self.alive.store(true, Ordering::SeqCst);
        let alive = self.alive.clone();
        let host = self.host;
        let port = self.port;
        let latest = self.latest.clone();

        self.handle = Some(thread::spawn(move || {
            // Setup connection initially:
            let mut reader: BufReader<&TcpStream>;
            let mut stream: TcpStream;
            'th: while alive.load(Ordering::SeqCst) {
                // Setup connection and do handshake
                'setup: loop {
                    if !alive.load(Ordering::SeqCst) {
                        break 'th;
                    }
                    stream = if let Ok(strm) = TcpStream::connect(format!("{}:{}", host, port)) {
                        strm
                    } else {
                        thread::sleep(Duration::from_secs(3));
                        continue;
                    };
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .expect("set_read_timeout call failed");

                    let mut r = io::BufReader::new(&stream);
                    let mut w = io::BufWriter::new(&stream);
                    if handshake(&mut r, &mut w).is_err() {
                        // Something went wrong in our handshake... let's try again...
                        thread::sleep(Duration::from_secs(3));
                        continue;
                    }
                    reader = r;
                    break 'setup;
                }

                while let Ok(msg) = get_data(&mut reader) {
                    if !alive.load(Ordering::SeqCst) {
                        break 'th;
                    }
                    match msg {
                        ResponseData::Tpv(t) => {
                            latest.lock().unwrap().update(GpsData {
                                lat: Some(t.lat.unwrap_or(0.0)),
                                lon: Some(t.lon.unwrap_or(0.0)),
                                alt: Some(t.alt.unwrap_or(0.0)),
                                speed: Some(t.speed.unwrap_or(0.0)),
                                heading: Some(t.track.unwrap_or(0.0)),
                                alt_g: Some(t.alt_hae.unwrap_or(0.0)),
                                eph: Some(t.eph.unwrap_or(0.0)),
                                epv: Some(t.epv.unwrap_or(0.0)),
                                fix: Some(t.mode as u8),
                                hdop: None,
                                vdop: None,
                                timestamp: Some(t.time.unwrap_or("".to_string())),
                            });
                        }
                        // SKY object reports a sky view of the GPS satellite positions.
                        ResponseData::Sky(sky) => {
                            /* let sats = sky.satellites.map_or_else(
                                || "(none)".to_owned(),
                                |sats| {
                                    sats.iter()
                                        .filter(|sat| sat.used)
                                        .map(|sat| sat.prn.to_string())
                                        .join(",") // Need itertools for this
                                },
                            ); */
                            latest.lock().unwrap().update(GpsData {
                                lat: None,
                                lon: None,
                                alt: None,
                                alt_g: None,
                                eph: None,
                                epv: None,
                                speed: None,
                                heading: None,
                                fix: None,
                                hdop: Some(sky.xdop.unwrap_or(0.0)),
                                vdop: Some(sky.ydop.unwrap_or(0.0)),
                                timestamp: None,
                            });
                        }
                        _ => {}
                    }
                }
                latest.lock().unwrap().reset();
            }
        }));
    }

    pub fn stop(&mut self) {
        self.alive.store(false, Ordering::SeqCst);
        self.handle
            .take()
            .expect("Called stop on non-running thread")
            .join()
            .expect("Could not join spawned thread");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Timestamp {
    high: u32,
    low: u32,
}

impl Timestamp {
    pub fn new(timestamp: u64) -> Self {
        let high = (timestamp >> 32) as u32;
        let low = (timestamp & 0xFFFFFFFF) as u32;
        Timestamp { high, low }
    }

    pub fn from_iso8601(time_str: &str) -> Result<Self, chrono::ParseError> {
        let datetime: DateTime<Utc> = time_str.parse()?;
        let duration_since_epoch = datetime.signed_duration_since(DateTime::UNIX_EPOCH);

        let total_nanos = (duration_since_epoch.num_seconds() as u64 * 1_000_000_000)
            + duration_since_epoch.num_nanoseconds().unwrap_or(0) as u64;

        let high = (total_nanos >> 32) as u32;
        let low = (total_nanos & 0xFFFFFFFF) as u32;

        Ok(Timestamp { high, low })
    }

    pub fn to_u64(self) -> u64 {
        ((self.high as u64) << 32) | self.low as u64
    }

    pub fn to_system_time(self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.to_u64())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FixedPoint {
    value: i64,
    decimal_places: u32,
}

impl FixedPoint {
    pub fn new(value: i64, decimal_places: u32) -> Self {
        FixedPoint {
            value,
            decimal_places,
        }
    }

    pub fn to_f64(self) -> f64 {
        let divisor = 10u64.pow(self.decimal_places) as f64;
        self.value as f64 / divisor
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Fixed3_7 {
    value: u32, // Internal representation, considering offset
}

impl Fixed3_7 {
    // Converts from a floating-point number to a Fixed3_7 representation
    pub fn from_float(flt: f64) -> Result<Self, &'static str> {
        if !(-180.0..=180.0).contains(&flt) {
            return Err("invalid value"); // Out of range values are considered illegal
        }

        let scaled: i64 = (flt * 10000000f64) as i64;
        let ret: u32 = (scaled + 1800000000i64) as u32;

        Ok(Fixed3_7 { value: ret })
    }

    // Converts the Fixed3_7 back to a floating-point number
    pub fn to_float(self) -> f64 {
        if self.value > 3600000000 {
            panic!("Value too much");
        }
        let remapped = self.value as i64 - (180 * 10000000);
        remapped as f64 / 10000000.0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Fixed3_6 {
    value: u32, // Encoded representation as a u32
}

impl Fixed3_6 {
    pub fn from_float(flt: f64) -> Result<Self, &'static str> {
        if !(0.0..=999.999999).contains(&flt) {
            return Err("invalid value"); // Out of range values are considered illegal
        }
        let scaled = (flt * 1_000_000.0) as u32; // Rounding done on f64
        Ok(Fixed3_6 { value: scaled })
    }

    // Converts the Fixed3_6 back to a floating-point number
    pub fn to_float(self) -> f64 {
        self.value as f64 / 1_000_000.0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Fixed6_4 {
    value: u32, // Internal representation considering offset and range
}

impl Fixed6_4 {
    pub fn from_float(flt: f32) -> Result<Self, &'static str> {
        if flt <= -180000.0001 || flt >= 180000.0001 {
            return Err("invalid value"); // Out of range values are considered illegal
        }
        let offset = 18_000_000 * 10_000;
        let scaled = ((flt * 10_000.0) as i64 + offset) as u32; // Rounding done on f64
        Ok(Fixed6_4 { value: scaled })
    }

    pub fn to_float(self) -> f64 {
        (self.value as i64 - 18_000_000 * 10_000) as f64 / 10_000.0
    }
}
