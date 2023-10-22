use libwifi::frame::*;
use libwifi::parse_frame;

#[test]
fn test_rts() {
    let payload = [
        180, 0, // FrameControl
        158, 0, // Duration
        116, 66, 127, 77, 29, 45, // First Address
        20, 125, 218, 170, 84, 81, // Second Address
    ];

    let frame = parse_frame(&payload).expect("Payload should be valid");
    println!("{frame:?}");
    assert!(matches!(frame, Frame::Rts(_)));
}

#[test]
fn test_cts() {
    let payload = [
        196, 0, // FrameControl
        246, 14, // Duration
        224, 62, 68, 8, 195, 239, // First Address
    ];

    let frame = parse_frame(&payload).expect("Payload should be valid");
    println!("{frame:?}");
    assert!(matches!(frame, Frame::Cts(_)));
}

#[test]
fn test_ack() {
    let payload = [
        212, 0, // FrameControl
        0, 0, // Duration
        104, 217, 60, 214, 195, 239, // First Address
    ];

    let frame = parse_frame(&payload).expect("Payload should be valid");
    println!("{frame:?}");
    assert!(matches!(frame, Frame::Ack(_)));
}

#[test]
fn test_single_tid_compressed_block_ack_request() {
    let payload = [
        132, 0, // FrameControl
        58, 1, // Duration
        192, 238, 251, 75, 207, 58, // First Address
        24, 29, 234, 198, 62, 190, // Second Address
        4, 0, // BlockAckRequest Control
        160, 15, // Starting sequence number of the single TID
    ];

    let frame = parse_frame(&payload).expect("Payload should be valid");
    println!("{frame:?}");
    assert!(matches!(frame, Frame::BlockAckRequest(_)));

    if let Frame::BlockAckRequest(inner) = frame {
        assert!(matches!(inner.mode, BlockAckMode::CompressedBlockAck));
    }
}

#[test]
fn test_compressed_bitmap_block_ack() {
    let payload = [
        148, 0, // FrameControl
        0, 0, // Duration
        192, 238, 251, 75, 207, 58, // First Address
        248, 50, 228, 173, 71, 184, // Second Address
        5, 0, // BlockAck Control
        144, 4, // BlockAck starting sequence control
        1, 0, 0, 0, 0, 0, 0, 0, // BlockAck Bitmap
    ];

    let frame = parse_frame(&payload).expect("Payload should be valid");
    println!("{frame:?}");
    assert!(matches!(frame, Frame::BlockAck(_)));

    if let Frame::BlockAck(inner) = frame {
        assert!(matches!(inner.mode, BlockAckMode::CompressedBlockAck));
    }
}
