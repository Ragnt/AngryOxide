#[allow(clippy::module_inception)]
mod data;
mod qos_data;

pub use data::*;
pub use qos_data::*;

use super::components::DataHeader;

// These make match statements much easier

pub trait DataFrame {
    fn header(&self) -> &DataHeader;
    fn eapol_key(&self) -> &Option<EapolKey>;
    fn data(&self) -> &Vec<u8>;
}

pub trait NullDataFrame {
    fn header(&self) -> &DataHeader;
}
