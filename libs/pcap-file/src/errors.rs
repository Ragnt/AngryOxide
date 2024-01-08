use thiserror::Error;

/// Result type for the pcap/pcapng parsing
pub type PcapResult<T> = Result<T, PcapError>;

/// Error type for the pcap/pcapng parsing
#[derive(Error, Debug)]
pub enum PcapError {
    /// Buffer too small
    #[error("Need more bytes")]
    IncompleteBuffer,

    /// Generic IO error
    #[error("Error reading bytes")]
    IoError(#[source] std::io::Error),

    /// Invalid field
    #[error("Invalid field value: {0}")]
    InvalidField(&'static str),

    /// UTF8 conversion error
    #[error("UTF8 error")]
    Utf8Error(#[source] std::str::Utf8Error),

    /// From UTF8 conversion error
    #[error("UTF8 error")]
    FromUtf8Error(#[source] std::string::FromUtf8Error),

    /// Invalid interface ID (only for Pcap NG)
    #[error("No corresponding interface id: {0}")]
    InvalidInterfaceId(u32),
}

impl From<std::str::Utf8Error> for PcapError {
    fn from(err: std::str::Utf8Error) -> Self {
        PcapError::Utf8Error(err)
    }
}

impl From<std::string::FromUtf8Error> for PcapError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        PcapError::FromUtf8Error(err)
    }
}
