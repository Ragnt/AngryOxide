use byteorder::{ByteOrder, LE};
use libwifi::frame::components::MacAddress;
use nl80211_ng::Interface;
use pcap_file::pcapng::blocks::enhanced_packet::{EnhancedPacketBlock, EnhancedPacketOption};
use pcap_file::pcapng::blocks::interface_description::{
    InterfaceDescriptionBlock, InterfaceDescriptionOption,
};
use pcap_file::pcapng::blocks::opt_common::CustomBinaryOption;
use pcap_file::pcapng::{PcapNgBlock, PcapNgWriter};
use pcap_file::DataLink;
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

use crate::gps::{self, GpsData};

#[derive(Clone)]
pub struct FrameData {
    timestamp: SystemTime,
    gps_data: Option<GpsData>,
    data: Vec<u8>,
}

impl FrameData {
    pub fn new(timestamp: SystemTime, data: Vec<u8>, gps_data: Option<GpsData>) -> Self {
        FrameData {
            timestamp,
            gps_data,
            data,
        }
    }
}

pub struct PcapWriter {
    handle: Option<thread::JoinHandle<()>>,
    alive: sync::Arc<AtomicBool>,
    tx: Sender<FrameData>,
    rx: Arc<Mutex<Receiver<FrameData>>>,
    writer: Arc<Mutex<PcapNgWriter<File>>>,
}

impl PcapWriter {
    pub fn new(interface: &Interface, filename: &str) -> PcapWriter {
        let (tx, rx) = mpsc::channel();

        let file = File::create(filename).expect("Error creating file");
        let mut pcap_writer = PcapNgWriter::new(file).unwrap();
        let mac = interface.mac.clone().unwrap();

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
        }
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
