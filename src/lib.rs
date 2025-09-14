//! AngryOxide library components
//!
//! This library exposes core components of AngryOxide for testing and integration purposes.

pub mod rawsocks;

#[cfg(target_os = "macos")]
pub mod airport;

#[cfg(target_os = "macos")]
pub mod wireless_diagnostics;

#[cfg(target_os = "macos")]
pub mod macos_interface;

#[cfg(target_os = "macos")]
pub mod macos_monitor;

pub mod interface;
pub mod util;
