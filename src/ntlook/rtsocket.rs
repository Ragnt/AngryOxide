use crate::ntlook::attr::*;
use crate::ntlook::interface::Interface;
use crate::ntlook::util::*;

use libwifi::frame::components::MacAddress;
use neli::consts::genl::{CtrlAttr, CtrlCmd};
use neli::consts::rtnl::{Arphrd, IffFlags, Ifla, RtAddrFamily, Rtm};
use neli::consts::{nl::GenlId, nl::NlmF, nl::NlmFFlags, socket::NlFamily};
use neli::err::NlError;
use neli::genl::Genlmsghdr;
use neli::nl::{NlPayload, Nlmsghdr};
use neli::rtnl::{Ifinfomsg, Rtattr};
use neli::socket::NlSocketHandle;
use neli::types::RtBuffer;

pub struct RtSocket {
    pub(crate) sock: NlSocketHandle,
}

impl RtSocket {
    pub fn connect() -> Result<Self, NlError<GenlId, Genlmsghdr<CtrlCmd, CtrlAttr>>> {
        let mut sock = NlSocketHandle::connect(NlFamily::Route, None, &[])?;
        Ok(Self { sock })
    }

    pub fn get_interface_status(
        &mut self,
        interface: &mut Interface,
    ) -> Result<Operstate, NlError> {
        let nlmsg = Nlmsghdr::new(
            None,
            Rtm::Getlink,
            NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
            None,
            None,
            NlPayload::Payload(Ifinfomsg::new(
                RtAddrFamily::Packet,
                Arphrd::Netrom,
                interface.index.unwrap(),
                IffFlags::empty(),
                IffFlags::empty(),
                RtBuffer::new(),
            )),
        );
        self.sock.send(nlmsg).unwrap();

        let iter = self.sock.iter::<Rtm, Ifinfomsg>(false);
        for msg in iter {
            match msg {
                Ok(p) => match p.get_payload() {
                    Ok(p) => {
                        let handle = p.rtattrs.get_attr_handle();
                        // Extract the ethernet address and assert its length
                        if let Ok(operstate) =
                            handle.get_attr_payload_as_with_len::<Vec<u8>>(Ifla::Operstate)
                        {
                            interface.state = Some(Operstate::from_u8(operstate[0]));
                            return Ok(Operstate::from_u8(operstate[0]));
                        } else {
                            println!("Ethernet address not found");
                        }
                    }
                    Err(p) => {
                        if format!("{}", p) != "This packet does not have a payload" {
                            println!("{}", p);
                        }
                    }
                },
                Err(p) => {
                    if format!("{}", p) != "This packet does not have a payload" {
                        println!("{}", p);
                    }
                }
            }
        }

        Ok(Operstate::Unknown)
    }

    pub fn set_interface_mac_random(&mut self, interface_index: i32) -> Result<(), NlError> {
        let mut rtattr: RtBuffer<Ifla, neli::types::Buffer> = RtBuffer::new();
        let mac = MacAddress::random().0;
        rtattr.push(Rtattr::new(None, Ifla::Address, &mac[..]).unwrap());

        self.sock
            .send(Nlmsghdr::new(
                None,
                Rtm::Newlink,
                NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
                None,
                None,
                NlPayload::Payload(Ifinfomsg::new(
                    RtAddrFamily::Unspecified,
                    Arphrd::None,
                    interface_index,
                    IffFlags::empty(),
                    IffFlags::empty(),
                    rtattr,
                )),
            ))
            .unwrap();

        let iter = self.sock.iter::<Rtm, Ifinfomsg>(false);
        for msg in iter {
            match msg {
                Ok(p) => match p.get_payload() {
                    Ok(p) => {
                        //println!("{:?}", p);
                    }
                    Err(p) => {
                        if format!("{}", p) != "This packet does not have a payload" {
                            println!("{}", p);
                        }
                    }
                },
                Err(p) => {
                    if format!("{}", p) != "This packet does not have a payload" {
                        println!("{}", p);
                    }
                }
            }
        }

        Ok(())
    }

    pub fn set_interface_mac(&mut self, interface_index: i32, mac: Vec<u8>) -> Result<(), NlError> {
        let mut rtattr = RtBuffer::new();
        rtattr.push(Rtattr::new(None, Ifla::Address, mac).unwrap());

        self.sock
            .send(Nlmsghdr::new(
                None,
                Rtm::Newlink,
                NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
                None,
                None,
                NlPayload::Payload(Ifinfomsg::new(
                    RtAddrFamily::Unspecified,
                    Arphrd::None,
                    interface_index,
                    IffFlags::empty(),
                    IffFlags::empty(),
                    rtattr,
                )),
            ))
            .unwrap();

        let iter = self.sock.iter::<Rtm, Ifinfomsg>(false);
        for msg in iter {
            match msg {
                Ok(p) => match p.get_payload() {
                    Ok(p) => {
                        //println!("{:?}", p);
                    }
                    Err(p) => {
                        if format!("{}", p) != "This packet does not have a payload" {
                            println!("{}", p);
                        }
                    }
                },
                Err(p) => {
                    if format!("{}", p) != "This packet does not have a payload" {
                        println!("{}", p);
                    }
                }
            }
        }

        Ok(())
    }

    pub fn set_interface_up(&mut self, interface_index: i32) -> Result<(), NlError> {
        self.sock
            .send(Nlmsghdr::new(
                None,
                Rtm::Newlink,
                NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
                None,
                None,
                NlPayload::Payload(Ifinfomsg::up(
                    RtAddrFamily::Unspecified,
                    Arphrd::None,
                    interface_index,
                    RtBuffer::new(),
                )),
            ))
            .unwrap();

        let iter = self.sock.iter::<Rtm, Ifinfomsg>(false);
        for msg in iter {
            match msg {
                Ok(p) => match p.get_payload() {
                    Ok(p) => {
                        //println!("{:?}", p);
                    }
                    Err(p) => {
                        if format!("{}", p) != "This packet does not have a payload" {
                            println!("{}", p);
                        }
                    }
                },
                Err(p) => {
                    if format!("{}", p) != "This packet does not have a payload" {
                        println!("{}", p);
                    }
                }
            }
        }

        Ok(())
    }

    pub fn set_interface_down(&mut self, interface_index: i32) -> Result<(), NlError> {
        let nlmsg = Nlmsghdr::new(
            None,
            Rtm::Newlink,
            NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
            None,
            None,
            NlPayload::Payload(Ifinfomsg::down(
                RtAddrFamily::Unspecified,
                Arphrd::None,
                interface_index,
                RtBuffer::new(),
            )),
        );
        self.sock.send(nlmsg).unwrap();

        let iter = self.sock.iter::<Rtm, Ifinfomsg>(false);
        for msg in iter {
            match msg {
                Ok(p) => match p.get_payload() {
                    Ok(p) => {
                        //println!("{:?}", p);
                    }
                    Err(p) => {
                        if format!("{}", p) != "This packet does not have a payload" {
                            println!("{}", p);
                        }
                    }
                },
                Err(p) => {
                    if format!("{}", p) != "This packet does not have a payload" {
                        println!("{}", p);
                    }
                }
            }
        }

        Ok(())
    }
}
