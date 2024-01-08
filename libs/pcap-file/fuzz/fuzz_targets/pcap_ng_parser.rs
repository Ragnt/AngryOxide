#![no_main]
use libfuzzer_sys::fuzz_target;
use pcap_file::pcapng::PcapNgParser;

fuzz_target!(|data: &[u8]| {
    if let Ok((rem, mut pcapng_parser)) = PcapNgParser::new(data) {
        let mut src = rem;

        while !src.is_empty() {
            let _ = pcapng_parser.next_block(src);
            src = &src[1..];
        }
    }
});
