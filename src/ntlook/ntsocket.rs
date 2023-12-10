use crate::ntlook::attr::*;
use crate::ntlook::channels::{BandList, FrequencyStatus, WiFiBand, WiFiChannel};
use crate::ntlook::cmd::Nl80211Cmd;
use crate::ntlook::interface::Interface;
use crate::ntlook::util::*;
use crate::ntlook::{NL_80211_GENL_NAME, NL_80211_GENL_VERSION};

use super::{ChannelData, Nl80211Iftype};
use neli::attr::{AttrHandle, Attribute};
use neli::consts::{nl::NlmF, nl::NlmFFlags, nl::Nlmsg, socket::NlFamily};
use neli::genl::{Genlmsghdr, Nlattr};
use neli::nl::{NlPayload, Nlmsghdr};
use neli::socket::NlSocketHandle;
use neli::types::{Buffer, GenlBuffer};

use std::fs;

/// A generic netlink socket to send commands and receive messages
pub struct NtSocket {
    pub(crate) sock: NlSocketHandle,
    pub(crate) family_id: u16,
}

impl NtSocket {
    /// Create a new nl80211 socket with netlink
    pub fn connect() -> Result<Self, String> {
        let mut sock =
            NlSocketHandle::connect(NlFamily::Generic, None, &[]).map_err(|e| e.to_string())?;
        sock.nonblock().map_err(|e| e.to_string())?;
        let family_id = sock
            .resolve_genl_family(NL_80211_GENL_NAME)
            .map_err(|e| e.to_string())?;
        Ok(Self { sock, family_id })
    }

    pub fn cmd_get_interface(
        &mut self,
        interface_index: Option<i32>,
    ) -> Result<Vec<Interface>, String> {
        let msghdr = Genlmsghdr::<Nl80211Cmd, Nl80211Attr>::new(
            Nl80211Cmd::CmdGetInterface,
            NL_80211_GENL_VERSION,
            {
                let mut attrs = GenlBuffer::new();
                if let Some(interface_index) = interface_index {
                    attrs.push(
                        Nlattr::new(false, false, Nl80211Attr::AttrIfindex, interface_index)
                            .unwrap(),
                    );
                }
                attrs
            },
        );

        let nlhdr: Nlmsghdr<u16, Genlmsghdr<Nl80211Cmd, Nl80211Attr>> = {
            let len = None;
            let nl_type = self.family_id;
            let flags = NlmFFlags::new(&[NlmF::Request, NlmF::Dump]);
            let seq = None;
            let pid = None;
            let payload = NlPayload::Payload(msghdr);
            Nlmsghdr::new(len, nl_type, flags, seq, pid, payload)
        };

        self.sock.send(nlhdr).map_err(|e| e.to_string())?;

        let iter = self
            .sock
            .iter::<Nlmsg, Genlmsghdr<Nl80211Cmd, Nl80211Attr>>(false);

        let mut retval: Vec<Interface> = Vec::new();

        for response in iter {
            let response = response.unwrap();
            match response.nl_type {
                Nlmsg::Noop => (),
                Nlmsg::Error => return Err("Error".to_string()),
                Nlmsg::Done => break,
                _ => {
                    let mut res: Interface = Interface::default();
                    if let Some(p) = response.nl_payload.get_payload() {
                        let handle = p.get_attr_handle();
                        res = Interface::try_from(handle).unwrap();
                    }
                    retval.push(res);
                }
            }
        }
        Ok(retval)
    }

    pub fn cmd_get_iftypes(
        &mut self,
        interface_index: Option<i32>,
    ) -> Result<Vec<Interface>, String> {
        let msghdr = Genlmsghdr::<Nl80211Cmd, Nl80211Attr>::new(
            Nl80211Cmd::CmdGetWiphy,
            NL_80211_GENL_VERSION,
            {
                let mut attrs = GenlBuffer::new();
                if let Some(interface_index) = interface_index {
                    attrs.push(
                        Nlattr::new(false, false, Nl80211Attr::AttrIfindex, interface_index)
                            .unwrap(),
                    );
                }
                attrs
            },
        );

        let nlhdr: Nlmsghdr<u16, Genlmsghdr<Nl80211Cmd, Nl80211Attr>> = {
            let len = None;
            let nl_type = self.family_id;
            let flags = NlmFFlags::new(&[NlmF::Request, NlmF::Dump]);
            let seq = None;
            let pid = None;
            let payload = NlPayload::Payload(msghdr);
            Nlmsghdr::new(len, nl_type, flags, seq, pid, payload)
        };

        self.sock.send(nlhdr).map_err(|err| err.to_string())?;

        let iter = self
            .sock
            .iter::<Nlmsg, Genlmsghdr<Nl80211Cmd, Nl80211Attr>>(false);

        let mut retval: Vec<Interface> = Vec::new();

        for response in iter {
            let response = response.unwrap();
            match response.nl_type {
                Nlmsg::Noop => (),
                Nlmsg::Error => panic!("Error"),
                Nlmsg::Done => break,
                _ => {
                    let mut res = Interface::default();
                    match response.nl_payload.get_payload() {
                        Some(p) => {
                            let handle = p.get_attr_handle();
                            for attr in handle.get_attrs() {
                                match attr.nla_type.nla_type {
                                    Nl80211Attr::AttrSupportedIftypes => {
                                        res.iftypes = Some(decode_iftypes(
                                            attr.get_payload_as_with_len()
                                                .map_err(|err| err.to_string())?,
                                        ));
                                    }
                                    _ => {}
                                }
                            }
                        }
                        None => {}
                    }
                    retval.push(res);
                }
            }
        }

        Ok(retval)
    }

    pub fn cmd_get_split_wiphy<'a>(
        &mut self,
        interface: &'a mut Interface,
    ) -> Result<&'a mut Interface, String> {
        let msghdr = Genlmsghdr::<Nl80211Cmd, Nl80211Attr>::new(
            Nl80211Cmd::CmdGetWiphy,
            NL_80211_GENL_VERSION,
            {
                let mut attrs = GenlBuffer::new();
                if let Some(interface_index) = interface.index {
                    attrs.push(
                        Nlattr::new(
                            false,
                            false,
                            Nl80211Attr::AttrSplitWiphyDump,
                            interface_index,
                        )
                        .unwrap(),
                    );
                }
                attrs
            },
        );

        let nlhdr: Nlmsghdr<u16, Genlmsghdr<Nl80211Cmd, Nl80211Attr>> = {
            let len = None;
            let nl_type = self.family_id;
            let flags = NlmFFlags::new(&[NlmF::Request, NlmF::Dump]);
            let seq = None;
            let pid = None;
            let payload = NlPayload::Payload(msghdr);
            Nlmsghdr::new(len, nl_type, flags, seq, pid, payload)
        };

        self.sock.send(nlhdr).map_err(|err| err.to_string())?;

        let iter = self
            .sock
            .iter::<Nlmsg, Genlmsghdr<Nl80211Cmd, Nl80211Attr>>(false);

        for response in iter {
            let response = response.unwrap();
            match response.nl_type {
                Nlmsg::Noop => (),
                Nlmsg::Error => panic!("Error"),
                Nlmsg::Done => break,
                _ => {
                    if let Some(p) = response.nl_payload.get_payload() {
                        let handle = p.get_attr_handle();
                        for attr in handle.get_attrs() {
                            match attr.nla_type.nla_type {
                                Nl80211Attr::AttrWiphy => {
                                    let wiphyname: u32 =
                                        attr.get_payload_as().map_err(|err| err.to_string())?;
                                    let driver_path = format!(
                                        "/sys/class/ieee80211/phy{}/device/driver",
                                        wiphyname
                                    );

                                    if let Ok(link_path) = fs::read_link(&driver_path) {
                                        if let Some(driver_name) = link_path.file_name() {
                                            if let Some(driver_name_str) = driver_name.to_str() {
                                                interface.driver =
                                                    Some(driver_name_str.to_string());
                                            }
                                        }
                                    }
                                }
                                Nl80211Attr::AttrSupportedIftypes => {
                                    interface.iftypes = Some(decode_iftypes(
                                        attr.get_payload_as_with_len()
                                            .map_err(|err| err.to_string())?,
                                    ));
                                    interface.has_netlink = Some(true);
                                }
                                Nl80211Attr::AttrWiphyBands => {
                                    let handle: AttrHandle<
                                        '_,
                                        GenlBuffer<Nl80211Bandc, Buffer>,
                                        Nlattr<Nl80211Bandc, Buffer>,
                                    > = attr.get_attr_handle().unwrap();
                                    let bands = handle.get_attrs();
                                    let mut supported_bands: Vec<BandList> = Vec::new();
                                    for band in bands {
                                        let mut bandlist = BandList::default();

                                        match band.nla_type.nla_type {
                                            Nl80211Bandc::Band2ghz => {
                                                bandlist.band = WiFiBand::Band2GHz
                                            }
                                            Nl80211Bandc::Band5ghz => {
                                                bandlist.band = WiFiBand::Band5GHz
                                            }
                                            Nl80211Bandc::Band60ghz => todo!(),
                                            Nl80211Bandc::UnrecognizedConst(_) => todo!(),
                                        }
                                        let bandhandle: AttrHandle<
                                            '_,
                                            GenlBuffer<Nl80211BandAttr, Buffer>,
                                            Nlattr<Nl80211BandAttr, Buffer>,
                                        > = band.get_attr_handle().unwrap();
                                        for bandattr in bandhandle.get_attrs() {
                                            match bandattr.nla_type.nla_type {
                                                Nl80211BandAttr::BandAttrFreqs => {
                                                    let freqhandle: AttrHandle<
                                                        '_,
                                                        GenlBuffer<u16, Buffer>,
                                                        Nlattr<u16, Buffer>,
                                                    > = bandattr.get_attr_handle().unwrap();
                                                    let mut channels: Vec<ChannelData> =
                                                        [].to_vec();
                                                    for freq in freqhandle.get_attrs() {
                                                        let freqdata_handle: AttrHandle<
                                                            '_,
                                                            GenlBuffer<
                                                                Nl80211FrequencyAttr,
                                                                Buffer,
                                                            >,
                                                            Nlattr<Nl80211FrequencyAttr, Buffer>,
                                                        > = freq.get_attr_handle().unwrap();
                                                        let mut channel: ChannelData =
                                                            ChannelData::default();
                                                        for freqattr in freqdata_handle.get_attrs()
                                                        {
                                                            match freqattr.nla_type.nla_type {
                                                                    Nl80211FrequencyAttr::FrequencyAttrFreq => {
                                                                        let frequency: u32 = freqattr.get_payload_as().map_err(|err| err.to_string())?;
                                                                        channel.frequency = frequency;
                                                                        if let Some(chan) = WiFiChannel::from_frequency(frequency) {
                                                                            channel.channel = chan
                                                                        } else {
                                                                            println!("Unrecognized Frequency: {}", channel.frequency);
                                                                        }
                                                                    }
                                                                    Nl80211FrequencyAttr::FrequencyAttrDisabled => {
                                                                        channel.status = FrequencyStatus::Disabled;
                                                                    },
                                                                    Nl80211FrequencyAttr::FrequencyAttrMaxTxPower => {
                                                                        channel.pwr = freqattr.get_payload_as().map_err(|err| err.to_string())?;
                                                                    },
                                                                    _ => {}
                                                                }
                                                        }
                                                        channels.push(channel);
                                                    }
                                                    bandlist.channels = channels;
                                                }
                                                Nl80211BandAttr::BandAttrInvalid => {}
                                                Nl80211BandAttr::BandAttrRates => {}
                                                Nl80211BandAttr::BandAttrHtMcsSet => {}
                                                Nl80211BandAttr::BandAttrHtCapa => {}
                                                Nl80211BandAttr::BandAttrHtAmpduFactor => {}
                                                Nl80211BandAttr::BandAttrHtAmpduDensity => {}
                                                Nl80211BandAttr::BandAttrVhtMcsSet => {}
                                                Nl80211BandAttr::BandAttrVhtCapa => {}
                                                Nl80211BandAttr::UnrecognizedConst(_) => {}
                                            }
                                        }
                                        supported_bands.push(bandlist);
                                    }
                                    if !supported_bands.is_empty() {
                                        interface.frequency_list = Some(supported_bands);
                                    }
                                }
                                Nl80211Attr::AttrFeatureFlags => {
                                    const NL80211_FEATURE_ACTIVE_MONITOR: u32 = 1 << 17;
                                    let feature_flags: u32 =
                                        attr.get_payload_as().map_err(|err| err.to_string())?;
                                    if feature_flags & NL80211_FEATURE_ACTIVE_MONITOR != 0 {
                                        interface.active_monitor = Some(true);
                                    } else {
                                        interface.active_monitor = Some(false);
                                    }

                                    // This returns Some(true)
                                    println!("Set {:?}, {:?}", String::from_utf8(interface.name.clone().unwrap_or_default()), interface.active_monitor);
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
        // This returns Some(false)
        println!("Return {:?}, {:?}", String::from_utf8(interface.name.clone().unwrap_or_default()), interface.active_monitor);
        Ok(interface)
    }

    pub fn set_type_vec(
        &mut self,
        interface_index: i32,
        iftype: Nl80211Iftype,
        active: Option<bool>
    ) -> Result<(), String> {
        let msghdr = Genlmsghdr::<Nl80211Cmd, Nl80211Attr>::new(
            Nl80211Cmd::CmdSetInterface,
            NL_80211_GENL_VERSION,
            {
                let mut attrs = GenlBuffer::new();
                attrs.push(
                    Nlattr::new(false, false, Nl80211Attr::AttrIfindex, interface_index).unwrap(),
                );
                let iftype_value: u16 = iftype.into();
                attrs.push(
                    Nlattr::new(false, false, Nl80211Attr::AttrIftype, iftype_value as u32)
                        .unwrap(),
                );
                if active.is_some_and(|f| f) {
                    attrs.push(
                        Nlattr::new(false, false, Nl80211Attr::AttrMntrFlags, Nl80211MntrFlags::MntrFlagActive)
                            .unwrap(),
                    );
                }
                attrs
            },
        );

        let nlhdr: Nlmsghdr<u16, Genlmsghdr<Nl80211Cmd, Nl80211Attr>> = {
            let len = None;
            let nl_type = self.family_id;
            let flags = NlmFFlags::new(&[NlmF::Request, NlmF::Ack]);
            let seq = None;
            let pid = None;
            let payload = NlPayload::Payload(msghdr);
            Nlmsghdr::new(len, nl_type, flags, seq, pid, payload)
        };

        // Send the Netlink message
        self.sock.send(nlhdr).map_err(|err| err.to_string())?;

        let iter = self
            .sock
            .iter::<Nlmsg, Genlmsghdr<Nl80211Cmd, Nl80211Attr>>(false);

        for response in iter.flatten() {
            match response.nl_type {
                Nlmsg::Noop => (),
                Nlmsg::Error => match response.nl_payload {
                    NlPayload::Ack(_ack) => continue,
                    NlPayload::Err(err) => {
                        return Err(err.to_string());
                    }
                    NlPayload::Payload(p) => {
                        return Err(format!("{:?}", p));
                    }
                    NlPayload::Empty => {
                        return Err("Payload was empty".to_string());
                    }
                },
                Nlmsg::Done => break,
                _ => (),
            }
        }
        Ok(())
    }

    pub fn set_powersave_off(&mut self, interface_index: i32) -> Result<(), String> {
        let gmsghdr = Genlmsghdr::<Nl80211Cmd, Nl80211Attr>::new(
            Nl80211Cmd::CmdSetWiphy,
            NL_80211_GENL_VERSION,
            {
                let mut attrs = GenlBuffer::new();
                attrs.push(
                    Nlattr::new(false, false, Nl80211Attr::AttrIfindex, interface_index).unwrap(),
                );
                attrs.push(
                    Nlattr::new(
                        false,
                        false,
                        Nl80211Attr::AttrPsState,
                        Nl80211PsState::PsDisabled,
                    )
                    .unwrap(),
                );
                attrs
            },
        );

        let nlhdr: Nlmsghdr<u16, Genlmsghdr<Nl80211Cmd, Nl80211Attr>> = {
            let len = None;
            let nl_type = self.family_id;
            let flags = NlmFFlags::new(&[NlmF::Request, NlmF::Ack]);
            let seq = None;
            let pid = None;
            let payload = NlPayload::Payload(gmsghdr);
            Nlmsghdr::new(len, nl_type, flags, seq, pid, payload)
        };

        // Send the Netlink message
        self.sock.send(nlhdr).map_err(|err| err.to_string())?;

        let iter = self
            .sock
            .iter::<Nlmsg, Genlmsghdr<Nl80211Cmd, Nl80211Attr>>(false);

        for response in iter.flatten() {
            match response.nl_type {
                Nlmsg::Noop => (),
                Nlmsg::Error => match response.nl_payload {
                    NlPayload::Ack(_ack) => continue,
                    NlPayload::Err(err) => {
                        return Err(err.to_string());
                    }
                    NlPayload::Payload(p) => {
                        return Err(format!("{:?}", p));
                    }
                    NlPayload::Empty => {
                        return Err("Payload was empty".to_string());
                    }
                },
                Nlmsg::Done => break,
                _ => (),
            }
        }
        Ok(())
    }

    pub fn set_frequency(
        &mut self,
        interface_index: i32,
        frequency: u32,
        chan_width: Nl80211ChanWidth,
        chan_type: Nl80211ChannelType,
    ) -> Result<(), String> {
        let gmsghdr = Genlmsghdr::<Nl80211Cmd, Nl80211Attr>::new(
            Nl80211Cmd::CmdSetWiphy,
            NL_80211_GENL_VERSION,
            {
                let mut attrs = GenlBuffer::new();
                attrs.push(
                    Nlattr::new(false, false, Nl80211Attr::AttrIfindex, interface_index).unwrap(),
                );
                attrs.push(
                    Nlattr::new(false, false, Nl80211Attr::AttrWiphyFreq, frequency).unwrap(),
                );
                attrs.push(
                    Nlattr::new(
                        false,
                        false,
                        Nl80211Attr::AttrChannelWidth,
                        u32::from(u16::from(chan_width)),
                    )
                    .unwrap(),
                );
                attrs.push(
                    Nlattr::new(
                        false,
                        false,
                        Nl80211Attr::AttrWiphyChannelType,
                        u32::from(u16::from(chan_type)),
                    )
                    .unwrap(),
                );
                attrs.push(
                    Nlattr::new(false, false, Nl80211Attr::AttrCenterFreq1, frequency).unwrap(),
                );
                attrs
            },
        );

        let nlhdr: Nlmsghdr<u16, Genlmsghdr<Nl80211Cmd, Nl80211Attr>> = {
            let len = None;
            let nl_type = self.family_id;
            let flags = NlmFFlags::new(&[NlmF::Request, NlmF::Ack]);
            let seq = None;
            let pid = None;
            let payload = NlPayload::Payload(gmsghdr);
            Nlmsghdr::new(len, nl_type, flags, seq, pid, payload)
        };

        // Send the Netlink message

        let _ = self.sock.send(nlhdr).map_err(|err| err.to_string());

        let iter = self
            .sock
            .iter::<Nlmsg, Genlmsghdr<Nl80211Cmd, Nl80211Attr>>(false);

        for response in iter.flatten() {
            match response.nl_type {
                Nlmsg::Noop => (),
                Nlmsg::Error => match response.nl_payload {
                    NlPayload::Ack(_ack) => continue,
                    NlPayload::Err(err) => {
                        return Err(err.to_string());
                    }
                    NlPayload::Payload(p) => {
                        return Err(format!("{:?}", p));
                    }
                    NlPayload::Empty => {
                        return Err("Payload was empty".to_string());
                    }
                },
                Nlmsg::Done => break,
                _ => (),
            }
        }
        Ok(())
    }
}

impl From<NtSocket> for NlSocketHandle {
    /// Returns the underlying generic netlink socket
    fn from(sock: NtSocket) -> Self {
        sock.sock
    }
}
