use libwifi::frame::Frame;
use libwifi::parse_frame;

#[test]
fn test_data() {
    let payload = [
        8, 98, // FrameControl
        0, 0, // Duration id
        51, 51, 255, 75, 207, 58, // First address
        248, 50, 228, 173, 71, 184, // Second address
        192, 238, 251, 75, 207, 58, // Third address
        80, 2, // SequencControl
        // The rest is data
        90, 7, 0, 96, 0, 0, 0, 0, 239, 46, 109, 235, 61, 58, 89, 37, 181, 238, 23, 98, 108, 29, 99,
        170, 28, 132, 136, 248, 109, 194, 64, 139, 35, 219, 22, 195, 40, 100, 32, 6, 7, 230, 5,
        102, 8, 116, 33, 165, 132, 177, 44, 2, 247, 88, 213, 77, 12, 122, 49, 105, 29, 74, 55, 207,
        160, 46, 181, 65, 63, 123, 109, 117, 156, 77, 0, 65, 14, 72, 91, 169, 153, 0, 55, 68, 180,
        178, 230, 66,
    ];

    let frame = parse_frame(&payload).expect("Payload should be valid");
    println!("{frame:?}");
    assert!(matches!(frame, Frame::Data(_)));
}

#[test]
fn test_null_data() {
    let _payload = [
        72, 17, //
        60, 0, //
        156, 128, 223, 131, 16, 180, //
        252, 25, 16, 16, 128, 171, //
        156, 128, 223, 131, 16, 180, 128, 43,
    ];
}

#[test]
fn test_qos_data() {
    let payload = [
        136, 66, // Frame Control
        44, 0, // Duration Id
        192, 238, 251, 75, 207, 58, // Address 1
        248, 50, 228, 173, 71, 184, // Address 2
        248, 50, 228, 173, 71, 184, // Address 3
        64, 119, // SequencControl
        0, 0, // QoS
        // The rest is data
        163, 23, 0, 32, 2, 0, 0, 0, 210, 141, 170, 200, 6, 91, 65, 22, 251, 155, 224, 22, 110, 76,
        229, 101, 87, 252, 180, 136, 190, 132, 133, 242, 93, 175, 106, 168, 63, 207, 128, 199, 200,
        20, 115, 79, 168, 50, 132, 160, 219, 152, 184, 110, 181, 105, 4, 153, 182, 129, 58, 87, 72,
        110, 194, 217, 192, 151, 89, 181, 161, 122, 249, 129, 201, 75, 6, 32, 158, 213, 21, 168,
    ];
    let frame = parse_frame(&payload).expect("Payload should be valid");
    println!("{frame:?}");
    assert!(matches!(frame, Frame::QosData(_)));
}
#[test]
fn test_qos_null() {
    let payload = [
        200, 1, // FrameControl
        58, 1, // Duration id
        248, 50, 228, 173, 71, 184, // First Address
        192, 238, 251, 75, 207, 58, // Second Address
        248, 50, 228, 173, 71, 184, // Third Address
        80, 106, // Sequence Control
        0, 0, // QoS Header
    ];

    let frame = parse_frame(&payload).expect("Payload should be valid");
    println!("{frame:?}");
    assert!(matches!(frame, Frame::QosNull(_)));
}
