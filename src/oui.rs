use libwifi::frame::components::MacAddress;

// Define bitmasks for different OUI lengths
const OUI_24_BIT_MASK: u64 = 0x0000FFFFFF000000;
const OUI_28_BIT_MASK: u64 = 0x0000FFFFFFF00000;
const OUI_36_BIT_MASK: u64 = 0x0000FFFFFFFFF000;

#[derive(Debug, Clone)]
pub struct OuiRecord {
    oui: u64, // Store OUI as an integer
    oui_length: u32,
    short_name: String,
    long_name: String,
}

impl OuiRecord {
    fn new(oui: u64, oui_length: u32, short_name: String, long_name: String) -> OuiRecord {
        OuiRecord {
            oui,
            oui_length,
            short_name,
            long_name,
        }
    }

    pub fn short_name(&self) -> String {
        self.short_name.clone()
    }

    pub fn long_name(&self) -> String {
        self.long_name.clone()
    }

    pub fn oui(&self) -> String {
        format!("{:02X}/{}", self.oui, self.oui_length)
    }
}

#[derive(Debug, Default)]
pub struct OuiDatabase {
    records: Vec<OuiRecord>, // Use u32 as the key
}

impl OuiDatabase {
    pub fn new() -> OuiDatabase {
        let mut db = OuiDatabase {
            records: Vec::new(),
        };
        db.parse_and_load_data();
        db
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    fn parse_and_load_data(&mut self) {
        let data = include_str!("../assets/manuf");

        for line in data.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue; // Skip comments and empty lines
            }

            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 3 {
                let oui_str = parts[0].split('/').next().unwrap_or("").trim();
                let oui_len_str = parts[0].split('/').next_back().unwrap_or("").trim();
                let oui = u64::from_str_radix(&oui_str.replace(':', ""), 16).unwrap_or(0);
                let oui_length: u32 = oui_len_str.parse().unwrap_or(24);
                let oui = match oui_length {
                    24 => oui << (48 - 24),
                    28 => oui << (48 - 32),
                    36 => oui << (48 - 40),
                    _ => 0,
                };
                let short_name = parts[1].trim().to_string();
                let long_name = parts[2].trim().to_string();
                let record = OuiRecord::new(oui, oui_length, short_name, long_name);
                self.records.push(record);
            }
        }
    }

    pub fn search(&self, mac_address: &MacAddress) -> Option<OuiRecord> {
        let mac_int: u64 = mac_address.to_u64();

        for record in &self.records {
            let mask = match record.oui_length {
                24 => OUI_24_BIT_MASK,
                28 => OUI_28_BIT_MASK,
                36 => OUI_36_BIT_MASK,
                _ => continue,
            };

            if mac_int & mask == record.oui & mask {
                return Some(record.clone());
            }
        }
        None
    }
}

/*
00:50:C5         	ADSTechnolog	ADS Technologies, Inc
00:69:67:E0/28   	TianjinLianw	Tianjin Lianwu Technology Co., Ltd.
00:50:C2:FF:F0/36	MSRSolutions	MSR-Solutions GmbH
*/
