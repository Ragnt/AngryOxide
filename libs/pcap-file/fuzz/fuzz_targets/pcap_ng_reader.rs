#![no_main]
use libfuzzer_sys::fuzz_target;
use pcap_file::pcapng::PcapNgReader;

fuzz_target!(|data: &[u8]| {
    if let Ok(mut pcapng_reader) = PcapNgReader::new(data) {
        while let Some(_block) = pcapng_reader.next_block() {}
    }
});
