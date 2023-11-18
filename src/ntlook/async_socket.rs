use crate::Attrs;
use crate::Bss;
use crate::Interface;
use crate::Nl80211Attr;
use crate::Nl80211Cmd;
use crate::Socket;
use crate::Station;
use crate::NL_80211_GENL_VERSION;
use neli::err::DeError;

use neli::consts::genl::{CtrlAttr, CtrlCmd};
use neli::consts::{nl::GenlId, nl::NlmF, nl::NlmFFlags, nl::Nlmsg};
use neli::err::NlError;
use neli::genl::{Genlmsghdr, Nlattr};
use neli::nl::{NlPayload, Nlmsghdr};
use neli::socket::tokio::NlSocket;
use neli::types::GenlBuffer;

/// A generic netlink socket to send commands and receive messages
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
pub struct AsyncSocket {
    sock: NlSocket,
    family_id: u16,
}

impl TryFrom<Socket> for AsyncSocket {
    type Error = std::io::Error;

    fn try_from(from: Socket) -> Result<Self, Self::Error> {
        Ok(Self {
            sock: NlSocket::new(from.sock)?,
            family_id: from.family_id,
        })
    }
}

impl AsyncSocket {
    /// Create a new nl80211 socket with netlink
    pub fn connect() -> Result<Self, NlError<GenlId, Genlmsghdr<CtrlCmd, CtrlAttr>>> {
        Ok(Socket::connect()?.try_into()?)
    }

    async fn get_info_vec<T>(
        &mut self,
        interface_index: Option<i32>,
        cmd: Nl80211Cmd,
    ) -> Result<Vec<T>, NlError>
    where
        T: for<'a> TryFrom<Attrs<'a, Nl80211Attr>, Error = DeError>,
    {
        let msghdr = Genlmsghdr::<Nl80211Cmd, Nl80211Attr>::new(cmd, NL_80211_GENL_VERSION, {
            let mut attrs = GenlBuffer::new();
            if let Some(interface_index) = interface_index {
                attrs.push(
                    Nlattr::new(false, false, Nl80211Attr::AttrIfindex, interface_index).unwrap(),
                );
            }
            attrs
        });

        let nlhdr = {
            let len = None;
            let nl_type = self.family_id;
            let flags = NlmFFlags::new(&[NlmF::Request, NlmF::Dump]);
            let seq = None;
            let pid = None;
            let payload = NlPayload::Payload(msghdr);
            Nlmsghdr::new(len, nl_type, flags, seq, pid, payload)
        };

        self.sock.send(&nlhdr).await?;

        let mut buf = Vec::new();
        let mut retval = Vec::new();

        loop {
            let res = self
                .sock
                .recv::<Nlmsg, Genlmsghdr<Nl80211Cmd, Nl80211Attr>>(&mut buf)
                .await?;
            for response in res {
                match response.nl_type {
                    Nlmsg::Noop => (),
                    Nlmsg::Error => panic!("Error"),
                    Nlmsg::Done => return Ok(retval),
                    _ => {
                        retval.push(
                            response
                                .nl_payload
                                .get_payload()
                                .unwrap()
                                .get_attr_handle()
                                .try_into()?,
                        );
                    }
                };
            }
        }
    }

    /// Get information for all your wifi interfaces
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use neli_wifi::AsyncSocket;
    /// # use std::error::Error;
    /// # async fn test() -> Result<(), Box<dyn Error>>{
    /// let wifi_interfaces = AsyncSocket::connect()?.get_interfaces_info().await?;
    /// for wifi_interface in wifi_interfaces {
    ///     println!("{:#?}", wifi_interface);
    /// }
    /// #   Ok(())
    /// # };
    ///```
    pub async fn get_interfaces_info(&mut self) -> Result<Vec<Interface>, NlError> {
        self.get_info_vec(None, Nl80211Cmd::CmdGetInterface).await
    }

    /// Get access point information for a specific interface
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use neli_wifi::AsyncSocket;
    /// # use std::error::Error;
    /// # async fn test() -> Result<(), Box<dyn Error>> {
    /// let mut socket = AsyncSocket::connect()?;
    /// // First of all we need to get wifi interface information to get more data
    /// let wifi_interfaces = socket.get_interfaces_info().await?;
    /// for wifi_interface in wifi_interfaces {
    ///     if let Some(index) = wifi_interface.index {
    ///         // Then for each wifi interface we can fetch station information
    ///         for station_info in socket.get_station_info(index).await? {
    ///             println!("{:#?}", station_info);
    ///         }
    ///     }
    /// }
    /// #   Ok(())
    /// # }
    ///```
    pub async fn get_station_info(
        &mut self,
        interface_index: i32,
    ) -> Result<Vec<Station>, NlError> {
        self.get_info_vec(Some(interface_index), Nl80211Cmd::CmdGetStation)
            .await
    }

    pub async fn get_bss_info(&mut self, interface_index: i32) -> Result<Vec<Bss>, NlError> {
        self.get_info_vec(Some(interface_index), Nl80211Cmd::CmdGetScan)
            .await
    }
}

impl From<AsyncSocket> for NlSocket {
    /// Returns the underlying generic netlink socket
    fn from(sock: AsyncSocket) -> Self {
        sock.sock
    }
}
