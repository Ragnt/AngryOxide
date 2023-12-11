use std::collections::HashMap;

use clap::builder::TypedValueParser;

use crate::ntlook::attr::*;
use crate::ntlook::channels::*;
use crate::ntlook::interface::Interface;

use crate::ntlook::ntsocket::NtSocket;
use crate::ntlook::rtsocket::RtSocket;

use super::Nl80211Iftype;

pub fn update_interfaces() -> Result<HashMap<u32, Interface>, String> {
    get_interfaces_info()
}

// netlink commands

fn get_interfaces_info() -> Result<HashMap<u32, Interface>, String> {
    let mut nt_socket: NtSocket = NtSocket::connect()?;
    let mut rt_socket: RtSocket = RtSocket::connect()?;

    let mut interfaces: HashMap<u32, Interface> = nt_socket.cmd_get_interfaces()?;
    let wiphy: Vec<Interface> = nt_socket.cmd_get_split_wiphy()?;

    for wiphy_interface in wiphy {
        if let Some(interface) = interfaces.get_mut(&wiphy_interface.phy.unwrap()) {
            interface.merge_with(wiphy_interface);
            interface.state = Some(rt_socket.get_interface_status(interface.index.unwrap())?);
            return Ok(interfaces);
        }
    }
    Err("Interface Not Found".to_string())
}

pub fn get_interface_info_idx(interface_index: i32) -> Result<Interface, String> {
    let mut nt_socket: NtSocket = NtSocket::connect()?;
    let mut rt_socket: RtSocket = RtSocket::connect()?;

    let mut interfaces: HashMap<u32, Interface> = nt_socket.cmd_get_interfaces()?;
    let wiphy: Vec<Interface> = nt_socket.cmd_get_split_wiphy()?;

    for wiphy_interface in wiphy {
        if let Some(interface) = interfaces.get_mut(&wiphy_interface.phy.unwrap()) {
            interface.merge_with(wiphy_interface);
            interface.state = Some(rt_socket.get_interface_status(interface.index.unwrap())?);
            if interface.index.unwrap() == interface_index {
                return Ok(interface.clone());
            }
        }
    }
    Err("Interface Not Found".to_string())
}

pub fn get_interface_info_name(interface_name: &String) -> Result<Interface, String> {
    let mut nt_socket: NtSocket = NtSocket::connect()?;
    let mut rt_socket: RtSocket = RtSocket::connect()?;

    let mut interfaces: HashMap<u32, Interface> = nt_socket.cmd_get_interfaces()?;
    let wiphy: Vec<Interface> = nt_socket.cmd_get_split_wiphy()?;
    for wiphy_interface in wiphy {
        if let Some(interface) = interfaces.get_mut(&wiphy_interface.phy.unwrap()) {
            println!(
                "Interface: {:#?} \nWiphy: {:#?}",
                interface, wiphy_interface
            );
            interface.merge_with(wiphy_interface);
            interface.state = Some(rt_socket.get_interface_status(interface.index.unwrap())?);
            println!("Merged: {:#?}", interface);
            let mut name = interface.name.clone().unwrap();
            name.truncate(interface_name.chars().count());
            let name = &String::from_utf8(name).unwrap();
            if name == interface_name {
                return Ok(interface.clone());
            }
        }
    }
    Err("Interface Not Found".to_string())
}

pub fn set_interface_monitor(interface_index: i32, active: bool) -> Result<(), String> {
    let mut nt_socket = NtSocket::connect()?;
    nt_socket.set_type_vec(interface_index, Nl80211Iftype::IftypeMonitor, Some(active))?;
    //let _ = update_interfaces();
    Ok(())
}

pub fn set_interface_station(interface_index: i32) -> Result<(), String> {
    let mut nt_socket = NtSocket::connect()?;
    nt_socket.set_type_vec(interface_index, Nl80211Iftype::IftypeStation, None)?;
    //let _ = update_interfaces();
    Ok(())
}

pub fn set_interface_chan(interface_index: i32, channel: u8) -> Result<(), String> {
    let mut nt_socket = NtSocket::connect()?;
    nt_socket.set_frequency(
        interface_index,
        WiFiChannel::new(channel).unwrap().to_frequency().unwrap(),
        Nl80211ChanWidth::ChanWidth20Noht,
        Nl80211ChannelType::ChanNoHt,
    )?;
    //let _ = update_interfaces();
    Ok(())
}

// rtnetlink commands- all use interface index.

pub fn set_interface_up(interface_index: i32) -> Result<(), String> {
    let mut rt_socket = RtSocket::connect()?;
    rt_socket.set_interface_up(interface_index)?;
    //let _ = update_interfaces();
    Ok(())
}

pub fn set_interface_down(interface_index: i32) -> Result<(), String> {
    let mut rt_socket = RtSocket::connect()?;
    rt_socket.set_interface_down(interface_index)?;
    //let _ = update_interfaces();
    Ok(())
}

pub fn set_interface_mac(interface_index: i32, mac: &[u8; 6]) -> Result<(), String> {
    let mut rt_socket = RtSocket::connect()?;
    rt_socket.set_interface_mac(interface_index, mac)?;
    //let _ = update_interfaces();
    Ok(())
}

pub fn set_interface_mac_random(interface_index: i32) -> Result<(), String> {
    let mut rt_socket = RtSocket::connect()?;
    rt_socket.set_interface_mac_random(interface_index)?;
    //let _ = update_interfaces();
    Ok(())
}
// This should only be called when "updating" an interface, so we won't update it after doing this.
fn get_interface_state(interface_index: i32) -> Result<Operstate, String> {
    let mut rt_socket = RtSocket::connect().map_err(|e| e.to_string())?;
    rt_socket.get_interface_status(interface_index)
}
