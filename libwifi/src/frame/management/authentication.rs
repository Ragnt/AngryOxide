use crate::frame::components::*;
use libwifi_macros::AddressHeader;

#[derive(Clone, Debug, AddressHeader)]
pub struct Authentication {
    pub header: ManagementHeader,
    pub auth_algorithm: u16,
    pub auth_seq: u16,
    pub status_code: u16,
    pub challenge_text: Option<Vec<u8>>,
}

impl Authentication {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // Serialize the ManagementHeader
        bytes.extend_from_slice(&self.header.encode());

        // Serialize auth_algorithm (2 bytes)
        bytes.extend_from_slice(&self.auth_algorithm.to_ne_bytes());

        // Serialize auth_seq (2 bytes)
        bytes.extend_from_slice(&self.auth_seq.to_ne_bytes());

        // Serialize status_code (2 bytes)
        bytes.extend_from_slice(&self.status_code.to_ne_bytes());

        // Serialize challenge_text (if present)
        if let Some(ref text) = self.challenge_text {
            // Depending on the 802.11 standard, you might need to include the length of the challenge text
            // For example: bytes.extend_from_slice(&(text.len() as u16).to_be_bytes());

            bytes.extend_from_slice(text);
        }

        bytes
    }
}

#[derive(Clone, Debug, AddressHeader)]
pub struct Deauthentication {
    pub header: ManagementHeader,
    pub reason_code: DeauthenticationReason,
}

impl Deauthentication {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // Serialize the ManagementHeader
        bytes.extend_from_slice(&self.header.encode());

        // Serialize reason_code (2 bytes)
        bytes.extend_from_slice(&(self.reason_code.clone() as u16).to_ne_bytes());

        bytes
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DeauthenticationReason {
    UnspecifiedReason = 1,
    PreviousAuthenticationNoLongerValid = 2,
    DeauthenticatedBecauseSTAIsLeaving = 3,
    DisassociatedDueToInactivity = 4,
    DisassociatedBecauseAPUnableToHandleAllSTAs = 5,
    Class2FrameReceivedFromNonauthenticatedSTA = 6,
    Class3FrameReceivedFromNonassociatedSTA = 7,
    DisassociatedBecauseSTALeavingBSS = 8,
    STARequestingReassociationNotAuthenticated = 9,
    DisassociatedBecauseOfPowerCapability = 10,
    DisassociatedBecauseOfSupportedChannels = 11,
    InvalidInformationElement = 13,
    MICFailure = 14,
    FourWayHandshakeTimeout = 15,
    GroupKeyHandshakeTimeout = 16,
    InformationElementInFourWayHandshakeDifferent = 17,
    InvalidGroupCipher = 18,
    InvalidPairwiseCipher = 19,
    InvalidAKMP = 20,
    UnsupportedRSNInformationElementVersion = 21,
    InvalidRSNInformationElementCapabilities = 22,
    IEEE8021XAuthenticationFailed = 23,
    CipherSuiteRejectedBecauseOfSecurityPolicy = 24,
    TDLSUnreachable = 25,
    TDLSUnspecifiedReason = 26,
    TDLSRejected = 27,
    TDLSRequestedTearDown = 28,
    TDLSChannelSwitching = 30,
    UnauthorizedAccessPoint = 31,
    PriorAuthenticationValid = 32,
    ExternalServiceRequirements = 33,
    InvalidFTActionFrameCount = 34,
    InvalidPMKID = 35,
    InvalidMDE = 36,
    InvalidFTE = 37,
    SMECancelsAuthentication = 38,
    PeerUnreachable = 39,
    PeerDeauthenticatedForListenIntervalTooLarge = 41,
    DisassociatedForReasonUnspecified = 42,
    PeerDeauthenticatedForReasonUnspecified = 43,
    DisassociatedForSensorStation = 44,
    DisassociatedForPoorChannelConditions = 45,
    DisassociatedForBSSTransitionManagement = 46,
    DeauthenticatedForReasonUnspecified = 47,
    SessionInformationUnavailable = 48,
    DisassociatedForSCPRequestUnsuccessful = 49,
    DeauthenticatedForSCPRequestUnsuccessful = 50,
    Unknown,
}

impl DeauthenticationReason {
    pub fn from_code(code: u16) -> Self {
        match code {
            1 => DeauthenticationReason::UnspecifiedReason,
            2 => DeauthenticationReason::PreviousAuthenticationNoLongerValid,
            3 => DeauthenticationReason::DeauthenticatedBecauseSTAIsLeaving,
            4 => DeauthenticationReason::DisassociatedDueToInactivity,
            5 => DeauthenticationReason::DisassociatedBecauseAPUnableToHandleAllSTAs,
            6 => DeauthenticationReason::Class2FrameReceivedFromNonauthenticatedSTA,
            7 => DeauthenticationReason::Class3FrameReceivedFromNonassociatedSTA,
            8 => DeauthenticationReason::DisassociatedBecauseSTALeavingBSS,
            9 => DeauthenticationReason::STARequestingReassociationNotAuthenticated,
            10 => DeauthenticationReason::DisassociatedBecauseOfPowerCapability,
            11 => DeauthenticationReason::DisassociatedBecauseOfSupportedChannels,
            13 => DeauthenticationReason::InvalidInformationElement,
            14 => DeauthenticationReason::MICFailure,
            15 => DeauthenticationReason::FourWayHandshakeTimeout,
            16 => DeauthenticationReason::GroupKeyHandshakeTimeout,
            17 => DeauthenticationReason::InformationElementInFourWayHandshakeDifferent,
            18 => DeauthenticationReason::InvalidGroupCipher,
            19 => DeauthenticationReason::InvalidPairwiseCipher,
            20 => DeauthenticationReason::InvalidAKMP,
            21 => DeauthenticationReason::UnsupportedRSNInformationElementVersion,
            22 => DeauthenticationReason::InvalidRSNInformationElementCapabilities,
            23 => DeauthenticationReason::IEEE8021XAuthenticationFailed,
            24 => DeauthenticationReason::CipherSuiteRejectedBecauseOfSecurityPolicy,
            25 => DeauthenticationReason::TDLSUnreachable,
            26 => DeauthenticationReason::TDLSUnspecifiedReason,
            27 => DeauthenticationReason::TDLSRejected,
            28 => DeauthenticationReason::TDLSRequestedTearDown,
            30 => DeauthenticationReason::TDLSChannelSwitching,
            31 => DeauthenticationReason::UnauthorizedAccessPoint,
            32 => DeauthenticationReason::PriorAuthenticationValid,
            33 => DeauthenticationReason::ExternalServiceRequirements,
            34 => DeauthenticationReason::InvalidFTActionFrameCount,
            35 => DeauthenticationReason::InvalidPMKID,
            36 => DeauthenticationReason::InvalidMDE,
            37 => DeauthenticationReason::InvalidFTE,
            38 => DeauthenticationReason::SMECancelsAuthentication,
            39 => DeauthenticationReason::PeerUnreachable,
            41 => DeauthenticationReason::PeerDeauthenticatedForListenIntervalTooLarge,
            42 => DeauthenticationReason::DisassociatedForReasonUnspecified,
            43 => DeauthenticationReason::PeerDeauthenticatedForReasonUnspecified,
            44 => DeauthenticationReason::DisassociatedForSensorStation,
            45 => DeauthenticationReason::DisassociatedForPoorChannelConditions,
            46 => DeauthenticationReason::DisassociatedForBSSTransitionManagement,
            47 => DeauthenticationReason::DeauthenticatedForReasonUnspecified,
            48 => DeauthenticationReason::SessionInformationUnavailable,
            49 => DeauthenticationReason::DisassociatedForSCPRequestUnsuccessful,
            50 => DeauthenticationReason::DeauthenticatedForSCPRequestUnsuccessful,
            _ => DeauthenticationReason::Unknown,
        }
    }
}
