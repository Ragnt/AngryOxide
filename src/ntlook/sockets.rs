use crate::ntlook::attr::*;
use crate::ntlook::channels::*;
use crate::ntlook::interface::Interface;

use crate::ntlook::ntsocket::NtSocket;
use crate::ntlook::rtsocket::RtSocket;

use super::Nl80211Iftype;

pub fn update_interfaces() -> Result<Vec<Interface>, String> {
    get_interfaces_info()
}

// netlink commands

fn get_interfaces_info() -> Result<Vec<Interface>, String> {
    let mut nt_socket: NtSocket = NtSocket::connect()?;
    let mut rt_socket: RtSocket = RtSocket::connect()?;

    let mut interfaces: Vec<Interface> = nt_socket.cmd_get_interface(None)?;
    for interface in &mut interfaces {
        nt_socket.cmd_get_split_wiphy(interface)?;
        interface.state = Some(rt_socket.get_interface_status(interface.index.unwrap())?);
    }
    Ok(interfaces)
}

pub fn get_interface_info_idx(interface_index: i32) -> Result<Interface, String> {
    let mut nt_socket: NtSocket = NtSocket::connect()?;
    let mut rt_socket: RtSocket = RtSocket::connect()?;

    let mut interfaces = nt_socket.cmd_get_interface(Some(interface_index))?;
    for interface in &mut interfaces {
        nt_socket.cmd_get_split_wiphy(interface)?;
        interface.state = Some(rt_socket.get_interface_status(interface.index.unwrap())?);
    }
    Ok(interfaces.first().unwrap().clone())
}

pub fn get_interface_info_name(interface_name: &String) -> Result<Interface, String> {
    let mut nt_socket: NtSocket = NtSocket::connect()?;
    let mut rt_socket: RtSocket = RtSocket::connect()?;
    let mut ret_interface: Option<Interface> = None;
    let mut interfaces = nt_socket.cmd_get_interface(None)?;
    for interface in &mut interfaces {
        let name: String = if let Some(nme) = &interface.name {
            String::from_utf8(nme.to_vec())
                .unwrap()
                .trim_end_matches('\0')
                .to_owned()
        } else {
            continue;
        };
        if &name == interface_name {
            nt_socket.cmd_get_split_wiphy(interface)?;
            interface.state = Some(rt_socket.get_interface_status(interface.index.unwrap())?);
            ret_interface = Some(interface.clone());
            break;
        }
    }
    if let Some(intfc) = ret_interface {
        Ok(intfc)
    } else {
        Err("Interface Not Found".to_string())
    }
}

fn get_wiphy(interface: &mut Interface) -> Result<&mut Interface, String> {
    let mut nt_socket = NtSocket::connect()?;
    nt_socket.cmd_get_split_wiphy(interface)
}

pub fn set_interface_monitor(interface_index: i32) -> Result<(), String> {
    let mut nt_socket = NtSocket::connect()?;
    nt_socket.set_type_vec(interface_index, Nl80211Iftype::IftypeMonitor)?;
    let _ = update_interfaces();
    Ok(())
}

pub fn set_interface_station(interface_index: i32) -> Result<(), String> {
    let mut nt_socket = NtSocket::connect()?;
    nt_socket.set_type_vec(interface_index, Nl80211Iftype::IftypeStation)?;
    let _ = update_interfaces();
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
    let _ = update_interfaces();
    Ok(())
}

// rtnetlink commands- all use interface index.

pub fn set_interface_up(interface_index: i32) -> Result<(), String> {
    let mut rt_socket = RtSocket::connect()?;
    rt_socket.set_interface_up(interface_index)?;
    let _ = update_interfaces();
    Ok(())
}

pub fn set_interface_down(interface_index: i32) -> Result<(), String> {
    let mut rt_socket = RtSocket::connect()?;
    rt_socket.set_interface_down(interface_index)?;
    let _ = update_interfaces();
    Ok(())
}

pub fn set_interface_mac(interface_index: i32, mac: &[u8; 6]) -> Result<(), String> {
    let mut rt_socket = RtSocket::connect()?;
    rt_socket.set_interface_mac(interface_index, mac)?;
    let _ = update_interfaces();
    Ok(())
}

pub fn set_interface_mac_random(interface_index: i32) -> Result<(), String> {
    let mut rt_socket = RtSocket::connect()?;
    rt_socket.set_interface_mac_random(interface_index)?;
    let _ = update_interfaces();
    Ok(())
}
// This should only be called when "updating" an interface, so we won't update it after doing this.
fn get_interface_state(interface_index: i32) -> Result<Operstate, String> {
    let mut rt_socket = RtSocket::connect().map_err(|e| e.to_string())?;
    rt_socket.get_interface_status(interface_index)
}
