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

mod bss;
pub use bss::*;

mod station;
pub use station::*;

mod interface;
pub use interface::*;

mod socket;
pub use socket::*;

mod sockets;
pub use sockets::*;

mod rtsocket;
pub use rtsocket::*;

#[cfg(feature = "async")]
mod async_socket;
#[cfg(feature = "async")]
pub use async_socket::*;
