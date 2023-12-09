use crate::ntlook::attr::*;
extern crate rand;
use neli::consts::rtnl::{Arphrd, IffFlags, Ifla, RtAddrFamily, Rtm};
use neli::consts::{nl::NlmF, nl::NlmFFlags, socket::NlFamily};
use neli::nl::{NlPayload, Nlmsghdr};
use neli::rtnl::{Ifinfomsg, Rtattr};
use neli::socket::NlSocketHandle;
use neli::types::RtBuffer;
use rand::Rng;

pub struct RtSocket {
    pub(crate) sock: NlSocketHandle,
}

impl RtSocket {
    pub fn connect() -> Result<Self, String> {
        let sock =
            NlSocketHandle::connect(NlFamily::Route, None, &[]).map_err(|e| e.to_string())?;

        sock.nonblock().map_err(|e| e.to_string())?;
        Ok(Self { sock })
    }

    pub fn get_interface_status(&mut self, interface: i32) -> Result<Operstate, String> {
        let nlmsg = Nlmsghdr::new(
            None,
            Rtm::Getlink,
            NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
            None,
            None,
            NlPayload::Payload(Ifinfomsg::new(
                RtAddrFamily::Packet,
                Arphrd::Netrom,
                interface,
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
                            return Ok(Operstate::from_u8(operstate[0]));
                        } else {
                            return Err("Ethernet address not found".to_string());
                        }
                    }
                    Err(p) => {
                        if format!("{}", p) != "This packet does not have a payload" {
                            return Err(format!("{}", p));
                        }
                    }
                },
                Err(p) => {
                    if format!("{}", p) != "This packet does not have a payload" {
                        return Err(format!("{}", p));
                    }
                }
            }
        }

        Ok(Operstate::Unknown)
    }

    pub fn set_interface_mac_random(&mut self, interface_index: i32) -> Result<(), String> {
        let mut rtattr: RtBuffer<Ifla, neli::types::Buffer> = RtBuffer::new();
        let mac = generate_valid_mac();
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
                    Ok(_p) => {}
                    Err(p) => {
                        if format!("{}", p) != "This packet does not have a payload" {
                            return Err(format!("{}", p));
                        }
                    }
                },
                Err(p) => {
                    if format!("{}", p) != "This packet does not have a payload" {
                        return Err(format!("{}", p));
                    }
                }
            }
        }

        Ok(())
    }

    pub fn set_interface_mac(&mut self, interface_index: i32, mac: &[u8; 6]) -> Result<(), String> {
        let mut rtattr = RtBuffer::new();
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
                    Ok(_p) => {}
                    Err(p) => {
                        if format!("{}", p) != "This packet does not have a payload" {
                            return Err(format!("{}", p));
                        }
                    }
                },
                Err(p) => {
                    if format!("{}", p) != "This packet does not have a payload" {
                        return Err(format!("{}", p));
                    }
                }
            }
        }

        Ok(())
    }

    pub fn set_interface_up(&mut self, interface_index: i32) -> Result<(), String> {
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
                    Ok(_p) => {}
                    Err(p) => {
                        if format!("{}", p) != "This packet does not have a payload" {
                            return Err(format!("{}", p));
                        }
                    }
                },
                Err(p) => {
                    if format!("{}", p) != "This packet does not have a payload" {
                        return Err(format!("{}", p));
                    }
                }
            }
        }

        Ok(())
    }

    pub fn set_interface_down(&mut self, interface_index: i32) -> Result<(), String> {
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
                    Ok(_p) => {}
                    Err(p) => {
                        if format!("{}", p) != "This packet does not have a payload" {
                            return Err(format!("{}", p));
                        }
                    }
                },
                Err(p) => {
                    if format!("{}", p) != "This packet does not have a payload" {
                        return Err(format!("{}", p));
                    }
                }
            }
        }

        Ok(())
    }
}

fn generate_valid_mac() -> [u8; 6] {
    let mut rng = rand::thread_rng();

    loop {
        let mac: [u8; 6] = rng.gen();

        // Check the conditions within the same function
        if !(mac == [255, 255, 255, 255, 255, 255] || // is_broadcast
             (mac[0] == 1 && (mac[1] == 128 && mac[2] == 194)) || // is_groupcast or is_spanning_tree
             (mac[0] == 1 && mac[1] == 0 && mac[2] == 94) || // is_ipv4_multicast
             mac == [51, 51, 0, 0, 0, 0] || // is_ipv6_neighborhood_discovery
             (mac[0] == 51 && mac[1] == 51))
        {
            // is_ipv6_multicast
            return mac;
        }
    }
}
