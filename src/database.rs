use crate::interface::Interface;

use rusqlite::{params, Connection, Result};
use std::time::Duration;
use std::{
    sync::{
        self,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
        Arc, Mutex,
    },
    thread,
};

use crate::pcapng::FrameData;

pub struct DatabaseWriter {
    handle: Option<thread::JoinHandle<()>>,
    alive: sync::Arc<AtomicBool>,
    tx: Sender<FrameData>,
    rx: Arc<Mutex<Receiver<FrameData>>>,
    filename: String,
    datasource_uuid: String,
    datasource: Interface,
}

impl DatabaseWriter {
    pub fn new(filename: &str, datasource_uuid: String, datasource: Interface) -> DatabaseWriter {
        let (tx, rx) = mpsc::channel();

        DatabaseWriter {
            handle: None,
            alive: Arc::new(AtomicBool::new(false)),
            tx,
            rx: Arc::new(Mutex::new(rx)),
            filename: filename.to_owned(),
            datasource_uuid,
            datasource,
        }
    }

    pub fn send(&mut self, f: FrameData) {
        self.tx.send(f.clone()).unwrap();
    }

    pub fn start(&mut self) {
        self.alive.store(true, Ordering::SeqCst);
        let alive = self.alive.clone();
        let rx = self.rx.clone();
        let filename = self.filename.clone();
        let interface = self.datasource.clone();
        let datasource = self.datasource_uuid.clone();

        self.handle = Some(thread::spawn(move || {
            // Setup database file
            let conn = Connection::open(filename).unwrap();
            let _ = setup_database(&conn, datasource, interface);

            while alive.load(Ordering::SeqCst) {
                let frx =
                    if let Ok(frx) = rx.lock().unwrap().recv_timeout(Duration::from_millis(500)) {
                        frx
                    } else {
                        continue;
                    };
                add_frame(&conn, &frx);
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

pub fn setup_database(conn: &Connection, datasource: String, interface: Interface) -> Result<()> {
    // Create tables:

    // Kismet
    conn.execute(
        "create table if not exists KISMET (kismet_version TEXT, db_version INT, db_module TEXT)",
        params![],
    )?;
    conn.execute(
        "INSERT INTO KISMET (kismet_version, db_version, db_module) values (?1, ?2, ?3)",
        [
            String::from("2022.02.R1"),
            8.to_string(),
            String::from("kismetlog"),
        ],
    )?;

    // Alerts
    conn.execute(
        "create table if not exists alerts (ts_sec integer, ts_usec integer, phyname TEXT, devmac TEXT, lat REAL, lon REAL, header TEXT, json BLOB )",
        params![],
    )?;
    // Data
    conn.execute(
        "create table if not exists data (ts_sec integer, ts_usec integer, phyname TEXT, devmac TEXT, lat REAL, lon REAL, alt REAL, speed REAL, heading REAL, datasource TEXT, type TEXT, json BLOB )",
        params![],
    )?;
    // Datasources
    conn.execute(
        "create table if not exists datasources (uuid TEXT, typestring TEXT, definition TEXT, name TEXT, interface TEXT, json BLOB, UNIQUE(uuid) ON CONFLICT REPLACE)",
        params![],
    )?;
    conn.execute(
        "INSERT INTO datasources (uuid, typestring, definition, name, interface) values (?1, ?2, ?3, ?4, $5)",
        [
            datasource,
            String::from("linuxwifi"),
            interface.name_as_string(),
            interface.name_as_string(),
            interface.name_as_string(),
        ],
    )?;

    // Devices
    conn.execute(
        "create table if not exists devices (first_time INT, last_time INT, devkey TEXT, phyname TEXT, devmac TEXT, strongest_signal INT, min_lat REAL, min_lon REAL, max_lat REAL, max_lon REAL, avg_lat REAL, avg_lon REAL, bytes_data INT, type TEXT, device BLOB, UNIQUE(phyname, devmac) ON CONFLICT REPLACE)",
        params![],
    )?;
    // Messages
    conn.execute(
        "create table if not exists messages (ts_sec INT, lat REAL, lon REAL, msgtype TEXT, message TEXT )",
        params![],
    )?;
    // Packets
    conn.execute(
        "create table if not exists packets (ts_sec integer, ts_usec integer, phyname TEXT, sourcemac TEXT, destmac TEXT, transmac TEXT, frequency REAL, devkey TEXT, lat REAL, lon REAL, alt REAL, speed REAL, heading REAL, packet_len integer, signal integer, datasource TEXT, dlt integer, packet BLOB, error integer, tags TEXT, datarate REAL, hash integer, packetid integer )",
        params![],
    )?;
    // Snapshots
    conn.execute(
        "create table if not exists snapshots (ts_sec INT, ts_usec INT, lat REAL, lon REAL, snaptype TEXT, json BLOB )",
        params![],
    )?;

    Ok(())
}

fn add_frame(conn: &Connection, frx: &FrameData) {
    let packet_data = PacketData::new(frx);
    let _result = conn.execute(
        "INSERT INTO packets (ts_sec, ts_usec, phyname, sourcemac, destmac, transmac, frequency, devkey, lat, lon, alt, speed, heading, packet_len, signal, datasource, dlt, packet, error, tags, datarate, hash, packetid) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)",
        params![
            packet_data.ts_sec,
            packet_data.ts_usec,
            packet_data.phyname,
            packet_data.sourcemac,
            packet_data.destmac,
            packet_data.transmac,
            packet_data.frequency,
            packet_data.devkey,
            packet_data.lat,
            packet_data.lon,
            packet_data.alt,
            packet_data.speed,
            packet_data.heading,
            packet_data.packet_len,
            packet_data.signal,
            packet_data.datasource,
            packet_data.dlt,
            packet_data.packet,
            packet_data.error,
            packet_data.tags,
            packet_data.datarate,
            packet_data.hash,
            packet_data.packetid
        ],
    );
}

#[derive(Debug, Clone)]
pub struct PacketData {
    ts_sec: u64,
    ts_usec: u64,
    phyname: String,
    sourcemac: String,
    destmac: String,
    transmac: String,
    frequency: f64, // in KHz
    devkey: String, // Deprecated
    lat: f64,
    lon: f64,
    alt: f32,
    speed: f32,
    heading: f32,
    packet_len: usize,
    signal: i32, // in dBm or other
    datasource: String,
    dlt: i32,
    packet: Vec<u8>, // Raw binary packet content
    error: u8,
    tags: String,  // Arbitrary space-separated list of tags
    datarate: f64, // in mbit/sec
    hash: u32,     // CRC32
    packetid: u64,
}

impl PacketData {
    pub fn new(frx: &FrameData) -> Self {
        let lat = if let Some(gps) = &frx.gps_data {
            gps.lat.unwrap_or(0f64)
        } else {
            0f64
        };

        let lon = if let Some(gps) = &frx.gps_data {
            gps.lon.unwrap_or(0f64)
        } else {
            0f64
        };

        let alt = if let Some(gps) = &frx.gps_data {
            gps.alt.unwrap_or(0f32)
        } else {
            0f32
        };

        let speed = if let Some(gps) = &frx.gps_data {
            gps.speed.unwrap_or(0f32)
        } else {
            0f32
        };
        let heading = if let Some(gps) = &frx.gps_data {
            gps.heading.unwrap_or(0f32)
        } else {
            0f32
        };

        PacketData {
            ts_sec: frx.ts_sec(),
            ts_usec: frx.ts_usec(),
            phyname: "IEEE802.11".to_string(),
            sourcemac: frx.source.to_long_string(),
            destmac: frx.destination.to_long_string(),
            transmac: String::from("00:00:00:00:00:00"),
            frequency: frx.frequency.unwrap_or_default() * 1000.0,
            devkey: String::from("0"),
            lat,
            lon,
            alt,
            speed,
            heading,
            packet_len: frx.data.len(),
            signal: frx.signal.unwrap_or_default(),
            datasource: frx.datasource.hyphenated().to_string(),
            dlt: 127,
            packet: frx.data.clone(),
            error: 0,
            tags: String::from(""),
            datarate: frx.datarate.unwrap_or_default(),
            hash: frx.crc32(),
            packetid: frx.packetid,
        }
    }
}
