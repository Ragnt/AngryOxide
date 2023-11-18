use rand::{thread_rng, RngCore};

use super::Nl80211Iftype;

pub fn decode_iftypes(bytes: Vec<u8>) -> Vec<Nl80211Iftype> {
    bytes
        .chunks(4)
        .filter_map(|chunk| {
            if chunk.len() == 4 {
                match chunk[2] {
                    0 => Some(Nl80211Iftype::IftypeUnspecified),
                    1 => Some(Nl80211Iftype::IftypeAdhoc),
                    2 => Some(Nl80211Iftype::IftypeStation),
                    3 => Some(Nl80211Iftype::IftypeAp),
                    4 => Some(Nl80211Iftype::IftypeApVlan),
                    6 => Some(Nl80211Iftype::IftypeMonitor),
                    7 => Some(Nl80211Iftype::IftypeMeshPoint),
                    // Add other cases as needed
                    _ => None,
                }
            } else {
                None
            }
        })
        .collect()
}

pub fn generate_random_bytes(x: usize) -> Vec<u8> {
    let mut rng = thread_rng();
    let length = x;
    let mut bytes = vec![0u8; length];
    rng.fill_bytes(&mut bytes);
    // Ensure the first byte is even
    if !bytes.is_empty() {
        bytes[0] &= 0xFE; // 0xFE is 11111110 in binary
    }

    bytes
}
