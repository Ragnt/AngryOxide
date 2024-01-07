use nom::Needed;

use crate::frame::components::FrameControl;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// This library can't parse all subtypes yet.
    /// If you hit a frame subtype that isn't supported, this error will be thrown.
    /// The [FrameControl] header should be successfully parsed in all scenarios and can be used
    /// for debugging.
    /// The remaining data is passed as second parameter and can be used for debugging.
    #[error("This frame subtype isn't handled yet: {:?} ({:?})", .0.frame_subtype, .0.frame_type)]
    UnhandledFrameSubtype(FrameControl, Vec<u8>),
    #[error("A parsing failure occurred: \n{}\ndata: {:?}", .0, .1)]
    Failure(String, Vec<u8>),
    #[error("There wasn't enough data. {}", .0)]
    Incomplete(String),

    #[error("Libwifi cannot handle this specific protocol yet: {}", .0)]
    UnhandledProtocol(String),
}

impl From<nom::Err<nom::error::Error<&[u8]>>> for Error {
    /// Manually specify the conversion from a [nom::error::Error] to our own error.
    /// We need this conversion, since we work with slices.
    /// If nom's error is propagated through the program, we get lifetime issues as we can't hold
    /// ownership of that slice and thereby require a 'static.
    fn from(error: nom::Err<nom::error::Error<&[u8]>>) -> Self {
        match error {
            nom::Err::Incomplete(needed) => match needed {
                Needed::Size(size) => {
                    Error::Incomplete(format!("At least {size} bytes are missing"))
                }
                Needed::Unknown => Error::Incomplete(String::new()),
            },
            nom::Err::Failure(error) => Error::Failure(
                format!(
                    "An error occured while parsing the data: nom::ErrorKind is {:?}",
                    error.code
                ),
                error.input.to_vec(),
            ),
            nom::Err::Error(error) => Error::Failure(
                format!(
                    "An error occured while parsing the data: nom::ErrorKind is {:?}",
                    error.code
                ),
                error.input.to_vec(),
            ),
        }
    }
}
