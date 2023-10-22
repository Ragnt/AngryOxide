use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rand::{thread_rng, Rng};

use libwifi::parse_frame;

const BEACON_PAYLOAD: [u8; 272] = [
    // Header
    128, 0, // FrameControl
    0, 0, // Duration id
    255, 255, 255, 255, 255, 255, // First address
    248, 50, 228, 173, 71, 184, // Second address
    248, 50, 228, 173, 71, 184, // Third address
    96, 119, // SequencControl
    // Data start
    151, 161, 39, 206, 165, 0, 0, 0, // timestamp
    100, 0, // interval
    17, 4, // capability
    0, 15, 77, 121, 32, 102, 97, 99, 101, 32, 119, 104, 101, 110, 32, 73, 80, // SSID
    1, 8, 130, 132, 139, 150, 36, 48, 72, 108, // Supported rates
    3, 1, 9, //
    5, 4, 0, 3, 1, 0, //
    42, 1, 4, //
    47, 1, 4, //
    48, 20, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 12, 0, 50, 4, 12, 18,
    24, 96, //
    45, 26, 189, 25, 23, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, //
    61, 22, 9, 8, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
    74, 14, 20, 0, 10, 0, 44, 1, 200, 0, 20, 0, 5, 0, 25, 0, //
    127, 8, 1, 0, 0, 0, 0, 0, 0, 64, //
    221, 49, 0, 80, 242, 4, 16, 74, 0, 1, 16, 16, 68, 0, 1, 2, 16, 71, 0, 16, 190, 15, 245, 213,
    137, 177, 64, 140, 203, 243, 77, 29, 90, 130, 118, 247, 16, 60, 0, 1, 3, 16, 73, 0, 6, 0, 55,
    42, 0, 1, 32, //
    221, 9, 0, 16, 24, 2, 5, 0, 28, 0, 0, //
    221, 24, 0, 80, 242, 2, 1, 1, 132, 0, 3, 164, 0, 0, 39, 164, 0, 0, 66, 67, 94, 0, 98, 50, 47,
    0,
];

pub fn parse_beacon(crit: &mut Criterion) {
    let mut rng = thread_rng();
    let random: u8 = rng.gen();
    let mut payload = BEACON_PAYLOAD.clone();

    // Log raw byte throughput
    let mut group = crit.benchmark_group("parsers");
    group.throughput(Throughput::Bytes(BEACON_PAYLOAD.len() as u64));

    // Actual benchmarking logic
    group.bench_function("Parse beacon", |bencher| {
        bencher.iter(|| {
            payload[270] = random;
            assert!(parse_frame(&BEACON_PAYLOAD).is_ok())
        })
    });
    group.finish()
}

criterion_group!(benches, parse_beacon);
criterion_main!(benches);
