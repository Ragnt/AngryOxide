#![no_main]
use libfuzzer_sys::fuzz_target;
use pcap_file::pcap::PcapParser;

fuzz_target!(|data: &[u8]| {
    if let Ok((rem, pcap_parser)) = PcapParser::new(data) {
        let mut src = rem;

        while !src.is_empty() {
            let _ = pcap_parser.next_packet(src);
            src = &src[1..];
        }
    }
});
