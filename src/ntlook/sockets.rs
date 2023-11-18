use crate::ntlook::attr::*;
use crate::ntlook::channels::*;
use crate::ntlook::interface::Interface;

use neli::consts::genl::{CtrlAttr, CtrlCmd};
use neli::consts::nl::GenlId;
use neli::err::NlError;
use neli::genl::Genlmsghdr;

use crate::ntlook::rtsocket::RtSocket;
use crate::ntlook::socket::Socket;

use super::Nl80211Iftype;

pub struct Sockets {
    pub(crate) rtsock: RtSocket,
    pub(crate) gensock: Socket,
    pub(crate) interfaces: Vec<Interface>,
}

impl Sockets {
    pub fn print_interface(&mut self, interface_index: i32) {
        for interface in &self.interfaces {
            if interface.index.unwrap() == interface_index {
                println!("{}", interface.pretty_print());
            }
        }
    }

    pub fn print_interfaces(&mut self) {
        for interface in &self.interfaces {
            println!("{}", interface.pretty_print());
        }
    }

    pub fn update_interfaces(&mut self) -> Result<bool, NlError> {
        match self.gensock.cmd_get_interface(None) {
            Ok(vec) => self.interfaces = vec,
            Err(err) => {
                let mapped_error = NlError::new(err.to_string());
                return Err(mapped_error);
            }
        }
        for interface in &mut self.interfaces {
            match self.gensock.cmd_get_split_wiphy(interface) {
                Ok(result) => {}
                Err(err) => {
                    let mapped_error = NlError::new(err.to_string());
                    return Err(mapped_error);
                }
            }
        }
        for interface in &mut self.interfaces {
            if let Some(index) = interface.index {
                match self.rtsock.get_interface_status(interface) {
                    Ok(state) => {
                        interface.state = Some(state);
                    }
                    Err(err) => {
                        let mapped_error = NlError::new(err.to_string());
                        return Err(mapped_error);
                    }
                }
            }
        }
        Ok(true)
    }

    pub fn get_interfaces_info(&mut self) -> Result<Vec<Interface>, NlError> {
        self.gensock.cmd_get_interface(None)
    }

    pub fn get_interface_info(&mut self, interface_index: i32) -> Result<Vec<Interface>, NlError> {
        self.gensock.cmd_get_interface(Some(interface_index))
    }

    pub fn set_interface_monitor(&mut self, interface_index: i32) -> Result<(), NlError> {
        let _ = self
            .gensock
            .set_type_vec(interface_index, Nl80211Iftype::IftypeMonitor);
        let _ = self.update_interfaces();
        Ok(())
    }

    pub fn set_interface_station(&mut self, interface_index: i32) -> Result<(), NlError> {
        let _ = self
            .gensock
            .set_type_vec(interface_index, Nl80211Iftype::IftypeStation);
        let _ = self.update_interfaces();
        Ok(())
    }

    pub fn set_interface_chan(&mut self, interface_index: i32, channel: u8) -> Result<(), NlError> {
        let _ = self.gensock.set_frequency(
            interface_index,
            WiFiChannel::new(channel).unwrap().to_frequency().unwrap(),
            Nl80211ChanWidth::ChanWidth20Noht,
            Nl80211ChannelType::ChanNoHt,
        );
        let _ = self.update_interfaces();
        Ok(())
    }

    pub fn set_interface_up(&mut self, interface_index: i32) -> Result<(), NlError> {
        let _ = self.rtsock.set_interface_up(interface_index);
        let _ = self.update_interfaces();
        Ok(())
    }

    pub fn set_interface_down(&mut self, interface_index: i32) -> Result<(), NlError> {
        let _ = self.rtsock.set_interface_down(interface_index);
        let _ = self.update_interfaces();
        Ok(())
    }

    pub fn set_interface_mac(&mut self, interface_index: i32, mac: Vec<u8>) -> Result<(), NlError> {
        let _ = self.rtsock.set_interface_mac(interface_index, mac);
        let _ = self.update_interfaces();
        Ok(())
    }

    pub fn set_interface_mac_random(&mut self, interface_index: i32) -> Result<(), NlError> {
        let _ = self.rtsock.set_interface_mac_random(interface_index);
        let _ = self.update_interfaces();
        Ok(())
    }

    pub fn get_interface_status(&mut self, interface: &mut Interface) -> Result<(), NlError> {
        let _ = self.rtsock.get_interface_status(interface);
        let _ = self.update_interfaces();
        Ok(())
    }
}

pub struct SocketsBuilder {
    rtsock: Option<RtSocket>,
    gensock: Option<Socket>,
    interfaces: Option<Vec<Interface>>,
}

impl SocketsBuilder {
    // Creates a new builder instance
    pub fn new() -> Self {
        SocketsBuilder {
            rtsock: None,
            gensock: None,
            interfaces: None,
        }
    }

    // Initializes and connects RtSocket
    pub fn with_rtsocket(
        &mut self,
    ) -> Result<&Self, NlError<GenlId, Genlmsghdr<CtrlCmd, CtrlAttr>>> {
        let mut rtsock = RtSocket::connect()?;
        if let Some(interfaces) = &mut self.interfaces {
            for interface in interfaces {
                if let Some(index) = interface.index {
                    match rtsock.get_interface_status(interface) {
                        Ok(state) => {}
                        Err(err) => {
                            let mapped_error = NlError::new(err.to_string());
                            return Err(mapped_error);
                        }
                    }
                }
            }
        }
        self.rtsock = Some(rtsock);
        Ok(self)
    }

    // Initializes and connects Socket
    pub fn with_gensocket(
        &mut self,
    ) -> Result<&Self, NlError<GenlId, Genlmsghdr<CtrlCmd, CtrlAttr>>> {
        let mut gensock = Socket::connect()?;

        // Use a mutable reference to gensock for get_info_vec
        match gensock.cmd_get_interface(None) {
            Ok(vec) => self.interfaces = Some(vec),
            Err(err) => {
                let mapped_error = NlError::new(err.to_string());
                return Err(mapped_error);
            }
        }
        if let Some(interfaces) = &mut self.interfaces {
            for interface in interfaces {
                match gensock.cmd_get_split_wiphy(interface) {
                    Ok(result) => {}
                    Err(err) => {
                        let mapped_error = NlError::new(err.to_string());
                        return Err(mapped_error);
                    }
                }
            }
        }
        self.gensock = Some(gensock);
        Ok(self)
    }

    // Builds the Sockets struct
    pub fn build(mut self) -> Result<Sockets, &'static str> {
        self.with_gensocket();
        self.with_rtsocket();
        match (self.gensock, self.rtsock, self.interfaces) {
            (Some(gensock), Some(rtsock), Some(interfaces)) => Ok(Sockets {
                rtsock,
                gensock,
                interfaces,
            }),
            _ => Err("Both RtSocket and Socket must be initialized"),
        }
    }
}
