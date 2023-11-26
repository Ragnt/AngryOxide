#![cfg_attr(docsrs, feature(doc_cfg))]

pub const NL_80211_GENL_NAME: &str = "nl80211";
pub const NL_80211_GENL_VERSION: u8 = 1;

mod cmd;
pub use cmd::*;

mod attr;
pub use attr::*;

mod util;
pub use util::*;

mod channels;
pub use channels::*;

mod interface;
pub use interface::*;

mod ntsocket;
pub use ntsocket::*;

mod sockets;
pub use sockets::*;

mod rtsocket;
pub use rtsocket::*;
