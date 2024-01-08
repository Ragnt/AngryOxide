# pcap-file
Provides parsers, readers and writers for Pcap and PcapNg files.

For Pcap files see the pcap module.

For PcapNg files see the pcapng module.

[![Crates.io](https://img.shields.io/crates/v/pcap-file.svg)](https://crates.io/crates/pcap-file)
[![rustdoc](https://img.shields.io/badge/Doc-pcap--file-green.svg)](https://docs.rs/pcap-file/)
[![Crates.io](https://img.shields.io/crates/l/pcap-file.svg)](https://github.com/courvoif/pcap-file/blob/master/LICENSE)


## Documentation
<https://docs.rs/pcap-file>


## Installation
This crate is on [crates.io](https://crates.io/crates/pcap-file).
Add it to your `Cargo.toml`:

```toml
[dependencies]
pcap-file = "2.0.0-rc1"
```


## Examples

### PcapReader
```rust,no_run
use std::fs::File;
use pcap_file::pcap::PcapReader;

let file_in = File::open("test.pcap").expect("Error opening file");
let mut pcap_reader = PcapReader::new(file_in).unwrap();

// Read test.pcap
while let Some(pkt) = pcap_reader.next_packet() {
    //Check if there is no error
    let pkt = pkt.unwrap();

    //Do something
 }
```

### PcapNgReader
```rust,no_run
use std::fs::File;
use pcap_file::pcapng::PcapNgReader;

let file_in = File::open("test.pcapng").expect("Error opening file");
let mut pcapng_reader = PcapNgReader::new(file_in).unwrap();

// Read test.pcapng
while let Some(block) = pcapng_reader.next_block() {
    // Check if there is no error
    let block = block.unwrap();

    //  Do something
}
```


## Fuzzing
Currently there are 4 crude harnesses to check that the parser won't panic in any situation. To start fuzzing you must install `cargo-fuzz` with the command:
```bash
$ cargo install cargo-fuzz
```

And then, in the root of the repository, you can run the harnesses as:
```bash
$ cargo fuzz run pcap_reader
$ cargo fuzz run pcap_ng_reader
$ cargo fuzz run pcap_parser
$ cargo fuzz run pcap_ng_parser
```

Keep in mind that libfuzzer by default uses only one core, so you can either run all the harnesses in different terminals, or you can pass the `-jobs` and `-workers` attributes. More info can be found in its documentation [here](https://llvm.org/docs/LibFuzzer.html).
To get better crash reports add to you rust flags: `-Zsanitizer=address`. 
E.g.
```bash
RUSTFLAGS="-Zsanitizer=address" cargo fuzz run pcap_reader
```


## License
Licensed under MIT.


## Disclaimer
To test the library I used the excellent PcapNg testing suite provided by [hadrielk](https://github.com/hadrielk/pcapng-test-generator). 

