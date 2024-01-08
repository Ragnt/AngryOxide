#![no_main]
use libfuzzer_sys::fuzz_target;
use pcap_file::pcap::PcapReader;

fuzz_target!(|data: &[u8]| {
    if let Ok(mut pcap_reader) = PcapReader::new(data) {
        while let Some(_packet) = pcap_reader.next_packet() {}
    }
});
