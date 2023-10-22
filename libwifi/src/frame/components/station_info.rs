#[derive(Clone, Debug, Default)]
/// StationInfo is used to parse and store variable length fields that are often sent
/// with management frames.
///
/// Each field has an `id`, the length of the bytes for this field, and then payload of the field.
/// Since there's a large number of possible fields and many propriatary vendor-specific usages
/// of these fields, this generic solution is used to capture all of them.
///
/// It is also important to note that most of these fields won't be sent most of the time. \
/// All fields that are already handled by this library get their own field in the StationInfo
/// struct.
///
/// Since we cannot handle all all those elements, the bytes of all unhandled elements will
/// be saved in the `data` field under the respectiv element id.

pub struct StationInfo {
    pub supported_rates: Vec<f32>,
    pub ssid: Option<String>,
    pub ds_parameter_set: Option<u8>,
    pub tim: Option<Vec<u8>>,
    pub country_info: Option<Vec<u8>>,
    pub power_constraint: Option<u8>,
    pub ht_capabilities: Option<Vec<u8>>,
    pub vht_capabilities: Option<Vec<u8>>,
    pub data: Vec<(u8, Vec<u8>)>,
}
