use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rand::{thread_rng, Rng};

use libwifi::parse_frame;

const DATA_PAYLOAD: [u8; 112] = [
    8, 98, // FrameControl
    0, 0, // Duration id
    51, 51, 255, 75, 207, 58, // First address
    248, 50, 228, 173, 71, 184, // Second address
    192, 238, 251, 75, 207, 58, // Third address
    80, 2, // SequencControl
    90, 7, 0, 96, 0, 0, 0, 0, 239, 46, 109, 235, 61, 58, 89, 37, 181, 238, 23, 98, 108, 29, 99,
    170, 28, 132, 136, 248, 109, 194, 64, 139, 35, 219, 22, 195, 40, 100, 32, 6, 7, 230, 5, 102, 8,
    116, 33, 165, 132, 177, 44, 2, 247, 88, 213, 77, 12, 122, 49, 105, 29, 74, 55, 207, 160, 46,
    181, 65, 63, 123, 109, 117, 156, 77, 0, 65, 14, 72, 91, 169, 153, 0, 55, 68, 180, 178, 230, 66,
];

pub fn parse_data(crit: &mut Criterion) {
    // Add some random variable to prevent aggressive compiler optimizations;
    let mut rng = thread_rng();
    let random: u8 = rng.gen();
    let mut payload = DATA_PAYLOAD.clone();

    // Log raw byte throughput
    let mut group = crit.benchmark_group("parsers");
    group.throughput(Throughput::Bytes(DATA_PAYLOAD.len() as u64));

    // Actual benchmarking logic
    group.bench_function("Parse data", |bencher| {
        bencher.iter(|| {
            payload[111] = random;
            assert!(parse_frame(&payload).is_ok());
        })
    });
    group.finish()
}

criterion_group!(benches, parse_data);
criterion_main!(benches);
