use crate::interface::Interface;
use byteorder::LE;
use crc32fast::Hasher;
use libwifi::frame::components::MacAddress;
use pcap_file::pcapng::blocks::enhanced_packet::{EnhancedPacketBlock, EnhancedPacketOption};
use pcap_file::pcapng::blocks::interface_description::{
    InterfaceDescriptionBlock, InterfaceDescriptionOption,
};
use pcap_file::pcapng::blocks::opt_common::CustomBinaryOption;
use pcap_file::pcapng::blocks::section_header::{SectionHeaderBlock, SectionHeaderOption};
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::{DataLink, Endianness};
use std::borrow::Cow;
use std::fs::File;
use std::time::{Duration, UNIX_EPOCH};
use std::{
    sync::{
        self,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
        Arc, Mutex,
    },
    thread,
    time::SystemTime,
};
use uname::uname;
use uuid::Uuid;

use crate::gps::GpsData;

#[derive(Clone, Debug)]
pub struct FrameData {
    pub timestamp: SystemTime,
    pub packetid: u64,
    pub gps_data: Option<GpsData>,
    pub data: Vec<u8>,
    pub source: MacAddress,
    pub destination: MacAddress,
    pub frequency: Option<f64>,
    pub signal: Option<i32>,
    pub datarate: Option<f64>,
    pub datasource: Uuid,
}

impl FrameData {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        timestamp: SystemTime,
        packetid: u64,
        data: Vec<u8>,
        gps_data: Option<GpsData>,
        source: MacAddress,
        destination: MacAddress,
        frequency: Option<f64>,
        signal: Option<i32>,
        datarate: Option<f64>,
        datasource: Uuid,
    ) -> Self {
        FrameData {
            timestamp,
            packetid,
            gps_data,
            data,
            source,
            destination,
            frequency,
            signal,
            datarate,
            datasource,
        }
    }

    pub fn ts_sec(&self) -> u64 {
        match self.timestamp.duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs(),
            Err(_) => 0, // Handle timestamp before UNIX_EPOCH, return 0 or handle as needed
        }
    }

    pub fn ts_usec(&self) -> u64 {
        match self.timestamp.duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.subsec_micros() as u64,
            Err(_) => 0, // Handle timestamp before UNIX_EPOCH, return 0 or handle as needed
        }
    }

    pub fn crc32(&self) -> u32 {
        let mut hasher = Hasher::new();
        hasher.update(&self.data);
        hasher.finalize()
    }
}

pub struct PcapWriter {
    handle: Option<thread::JoinHandle<()>>,
    alive: sync::Arc<AtomicBool>,
    tx: Sender<FrameData>,
    rx: Arc<Mutex<Receiver<FrameData>>>,
    writer: Arc<Mutex<PcapNgWriter<File>>>,
    filename: String,
}

impl PcapWriter {
    pub fn new(interface: &Interface, filename: &str) -> PcapWriter {
        let (tx, rx) = mpsc::channel();

        let file = File::create(filename).expect("Error creating file");
        let (os, arch) = if let Ok(info) = uname() {
            (
                format!("{} {}", info.sysname, info.release),
                info.machine.to_string(),
            )
        } else {
            ("Unknown".to_string(), "Unknown".to_string())
        };

        let application = format!("AngryOxide {}", env!("CARGO_PKG_VERSION"));

        let shb = SectionHeaderBlock {
            endianness: Endianness::native(),
            major_version: 1,
            minor_version: 0,
            section_length: -1,
            options: vec![
                SectionHeaderOption::UserApplication(Cow::from(application)),
                SectionHeaderOption::OS(Cow::from(os)),
                SectionHeaderOption::Hardware(Cow::from(arch)),
            ],
        };

        let mut pcap_writer = PcapNgWriter::with_section_header(file, shb).unwrap();

        let mac = interface.mac.clone().unwrap_or_else(|| vec![0; 6]);
        let interface = InterfaceDescriptionBlock {
            linktype: DataLink::IEEE802_11_RADIOTAP,
            snaplen: 0x0000,
            options: vec![
                InterfaceDescriptionOption::IfName(Cow::from(interface.name_as_string())),
                InterfaceDescriptionOption::IfHardware(Cow::from(interface.driver_as_string())),
                InterfaceDescriptionOption::IfMacAddr(Cow::from(mac)),
            ],
        };

        let _ = pcap_writer.write_pcapng_block(interface);

        PcapWriter {
            handle: None,
            alive: Arc::new(AtomicBool::new(false)),
            tx,
            rx: Arc::new(Mutex::new(rx)),
            writer: Arc::new(Mutex::new(pcap_writer)),
            filename: filename.to_owned(),
        }
    }

    pub fn check_size(&self) -> u64 {
        self.writer
            .lock()
            .unwrap()
            .get_ref()
            .metadata()
            .unwrap()
            .len()
    }

    pub fn send(&mut self, f: FrameData) {
        self.tx.send(f.clone()).unwrap();
    }

    pub fn start(&mut self) {
        self.alive.store(true, Ordering::SeqCst);
        let alive = self.alive.clone();
        let rx = self.rx.clone();
        let writer = self.writer.clone();

        self.handle = Some(thread::spawn(move || {
            while alive.load(Ordering::SeqCst) {
                let frx =
                    if let Ok(frx) = rx.lock().unwrap().recv_timeout(Duration::from_millis(500)) {
                        frx
                    } else {
                        continue;
                    };

                if let Some(gps) = frx.gps_data {
                    let option_block = gps.create_option_block(); // Create and store the block
                    let custom_binary_option = CustomBinaryOption::from_slice::<LE>(
                        2989,
                        &option_block, // Borrow from the stored block
                    )
                    .unwrap();
                    let packet = EnhancedPacketBlock {
                        interface_id: 0,
                        timestamp: frx.timestamp.duration_since(UNIX_EPOCH).unwrap(),
                        original_len: frx.data.len() as u32,
                        data: frx.data.into(),
                        options: vec![EnhancedPacketOption::CustomBinary(custom_binary_option)],
                    };

                    let _ = writer.lock().unwrap().write_pcapng_block(packet);
                } else {
                    let packet = EnhancedPacketBlock {
                        interface_id: 0,
                        timestamp: frx.timestamp.duration_since(UNIX_EPOCH).unwrap(),
                        original_len: frx.data.len() as u32,
                        data: frx.data.into(),
                        options: vec![],
                    };

                    let _ = writer.lock().unwrap().write_pcapng_block(packet);
                };
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
