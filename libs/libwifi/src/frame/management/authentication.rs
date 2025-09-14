use std::fmt;

use crate::frame::components::*;
use libwifi_macros::AddressHeader;

pub const DEAUTHENTICATION_REASON_MAX: u8 = 46;

#[derive(Clone, Debug, AddressHeader)]
pub struct Authentication {
    pub header: ManagementHeader,
    pub auth_algorithm: u16,
    pub auth_seq: u16,
    pub status_code: u16,
    pub challenge_text: Option<Vec<u8>>,
    pub station_info: Option<StationInfo>,
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
            bytes.extend_from_slice(text);
        }

        if let Some(info) = &self.station_info {
            bytes.extend_from_slice(&info.encode());
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

pub enum DeauthenticationReasonMenu {
    PreviousAuthenticationNoLongerValid,
    DeauthenticatedBecauseSTAIsLeaving,
    DisassociatedDueToInactivity,
    DisassociatedBecauseAPUnableToHandleAllSTAs,
    Class2FrameReceivedFromNonauthenticatedSTA,
    Class3FrameReceivedFromNonassociatedSTA,
    DisassociatedBecauseSTALeavingBSS,
    STARequestingReassociationNotAuthenticated,
    DisassociatedBecauseOfPowerCapability,
    DisassociatedBecauseOfSupportedChannels,
    InvalidInformationElement,
    MICFailure,
    FourWayHandshakeTimeout,
    GroupKeyHandshakeTimeout,
    InformationElementInFourWayHandshakeDifferent,
    InvalidGroupCipher,
    InvalidPairwiseCipher,
    InvalidAKMP,
    UnsupportedRSNInformationElementVersion,
    InvalidRSNInformationElementCapabilities,
    IEEE8021XAuthenticationFailed,
    CipherSuiteRejectedBecauseOfSecurityPolicy,
    TDLSUnreachable,
    TDLSUnspecifiedReason,
    TDLSRejected,
    TDLSRequestedTearDown,
    TDLSChannelSwitching,
    UnauthorizedAccessPoint,
    PriorAuthenticationValid,
    ExternalServiceRequirements,
    InvalidFTActionFrameCount,
    InvalidPMKID,
    InvalidMDE,
    InvalidFTE,
    SMECancelsAuthentication,
    PeerUnreachable,
    PeerDeauthenticatedForListenIntervalTooLarge,
    DisassociatedForReasonUnspecified,
    PeerDeauthenticatedForReasonUnspecified,
    DisassociatedForSensorStation,
    DisassociatedForPoorChannelConditions,
    DisassociatedForBSSTransitionManagement,
    DeauthenticatedForReasonUnspecified,
    SessionInformationUnavailable,
    DisassociatedForSCPRequestUnsuccessful,
    DeauthenticatedForSCPRequestUnsuccessful,
    DisassociatedDueToPoorRSSI,
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
    DisassociatedDueToPoorRSSI = 71,
    Unknown,
}

impl DeauthenticationReasonMenu {
    pub fn from_idx(value: u8) -> Self {
        match value {
            0 => DeauthenticationReasonMenu::PreviousAuthenticationNoLongerValid,
            1 => DeauthenticationReasonMenu::DeauthenticatedBecauseSTAIsLeaving,
            2 => DeauthenticationReasonMenu::DisassociatedDueToInactivity,
            3 => DeauthenticationReasonMenu::DisassociatedBecauseAPUnableToHandleAllSTAs,
            4 => DeauthenticationReasonMenu::Class2FrameReceivedFromNonauthenticatedSTA,
            5 => DeauthenticationReasonMenu::Class3FrameReceivedFromNonassociatedSTA,
            6 => DeauthenticationReasonMenu::DisassociatedBecauseSTALeavingBSS,
            7 => DeauthenticationReasonMenu::STARequestingReassociationNotAuthenticated,
            8 => DeauthenticationReasonMenu::DisassociatedBecauseOfPowerCapability,
            9 => DeauthenticationReasonMenu::DisassociatedBecauseOfSupportedChannels,
            10 => DeauthenticationReasonMenu::InvalidInformationElement,
            11 => DeauthenticationReasonMenu::MICFailure,
            12 => DeauthenticationReasonMenu::FourWayHandshakeTimeout,
            13 => DeauthenticationReasonMenu::GroupKeyHandshakeTimeout,
            14 => DeauthenticationReasonMenu::InformationElementInFourWayHandshakeDifferent,
            15 => DeauthenticationReasonMenu::InvalidGroupCipher,
            16 => DeauthenticationReasonMenu::InvalidPairwiseCipher,
            17 => DeauthenticationReasonMenu::InvalidAKMP,
            18 => DeauthenticationReasonMenu::UnsupportedRSNInformationElementVersion,
            19 => DeauthenticationReasonMenu::InvalidRSNInformationElementCapabilities,
            20 => DeauthenticationReasonMenu::IEEE8021XAuthenticationFailed,
            21 => DeauthenticationReasonMenu::CipherSuiteRejectedBecauseOfSecurityPolicy,
            22 => DeauthenticationReasonMenu::TDLSUnreachable,
            23 => DeauthenticationReasonMenu::TDLSUnspecifiedReason,
            24 => DeauthenticationReasonMenu::TDLSRejected,
            25 => DeauthenticationReasonMenu::TDLSRequestedTearDown,
            26 => DeauthenticationReasonMenu::TDLSChannelSwitching,
            27 => DeauthenticationReasonMenu::UnauthorizedAccessPoint,
            28 => DeauthenticationReasonMenu::PriorAuthenticationValid,
            29 => DeauthenticationReasonMenu::ExternalServiceRequirements,
            30 => DeauthenticationReasonMenu::InvalidFTActionFrameCount,
            31 => DeauthenticationReasonMenu::InvalidPMKID,
            32 => DeauthenticationReasonMenu::InvalidMDE,
            33 => DeauthenticationReasonMenu::InvalidFTE,
            34 => DeauthenticationReasonMenu::SMECancelsAuthentication,
            35 => DeauthenticationReasonMenu::PeerUnreachable,
            36 => DeauthenticationReasonMenu::PeerDeauthenticatedForListenIntervalTooLarge,
            37 => DeauthenticationReasonMenu::DisassociatedForReasonUnspecified,
            38 => DeauthenticationReasonMenu::PeerDeauthenticatedForReasonUnspecified,
            39 => DeauthenticationReasonMenu::DisassociatedForSensorStation,
            40 => DeauthenticationReasonMenu::DisassociatedForPoorChannelConditions,
            41 => DeauthenticationReasonMenu::DisassociatedForBSSTransitionManagement,
            42 => DeauthenticationReasonMenu::DeauthenticatedForReasonUnspecified,
            43 => DeauthenticationReasonMenu::SessionInformationUnavailable,
            44 => DeauthenticationReasonMenu::DisassociatedForSCPRequestUnsuccessful,
            45 => DeauthenticationReasonMenu::DeauthenticatedForSCPRequestUnsuccessful,
            46 => DeauthenticationReasonMenu::DisassociatedDueToPoorRSSI,
            _ => panic!("Unknown DeauthenticationReasonMenu value: {}", value),
        }
    }

    pub fn to_reason(&self) -> DeauthenticationReason {
        match self {
            DeauthenticationReasonMenu::PreviousAuthenticationNoLongerValid => {
                DeauthenticationReason::PreviousAuthenticationNoLongerValid
            }
            DeauthenticationReasonMenu::DeauthenticatedBecauseSTAIsLeaving => {
                DeauthenticationReason::DeauthenticatedBecauseSTAIsLeaving
            }
            DeauthenticationReasonMenu::DisassociatedDueToInactivity => {
                DeauthenticationReason::DisassociatedDueToInactivity
            }
            DeauthenticationReasonMenu::DisassociatedBecauseAPUnableToHandleAllSTAs => {
                DeauthenticationReason::DisassociatedBecauseAPUnableToHandleAllSTAs
            }
            DeauthenticationReasonMenu::Class2FrameReceivedFromNonauthenticatedSTA => {
                DeauthenticationReason::Class2FrameReceivedFromNonauthenticatedSTA
            }
            DeauthenticationReasonMenu::Class3FrameReceivedFromNonassociatedSTA => {
                DeauthenticationReason::Class3FrameReceivedFromNonassociatedSTA
            }
            DeauthenticationReasonMenu::DisassociatedBecauseSTALeavingBSS => {
                DeauthenticationReason::DisassociatedBecauseSTALeavingBSS
            }
            DeauthenticationReasonMenu::STARequestingReassociationNotAuthenticated => {
                DeauthenticationReason::STARequestingReassociationNotAuthenticated
            }
            DeauthenticationReasonMenu::DisassociatedBecauseOfPowerCapability => {
                DeauthenticationReason::DisassociatedBecauseOfPowerCapability
            }
            DeauthenticationReasonMenu::DisassociatedBecauseOfSupportedChannels => {
                DeauthenticationReason::DisassociatedBecauseOfSupportedChannels
            }
            DeauthenticationReasonMenu::InvalidInformationElement => {
                DeauthenticationReason::InvalidInformationElement
            }
            DeauthenticationReasonMenu::MICFailure => DeauthenticationReason::MICFailure,
            DeauthenticationReasonMenu::FourWayHandshakeTimeout => {
                DeauthenticationReason::FourWayHandshakeTimeout
            }
            DeauthenticationReasonMenu::GroupKeyHandshakeTimeout => {
                DeauthenticationReason::GroupKeyHandshakeTimeout
            }
            DeauthenticationReasonMenu::InformationElementInFourWayHandshakeDifferent => {
                DeauthenticationReason::InformationElementInFourWayHandshakeDifferent
            }
            DeauthenticationReasonMenu::InvalidGroupCipher => {
                DeauthenticationReason::InvalidGroupCipher
            }
            DeauthenticationReasonMenu::InvalidPairwiseCipher => {
                DeauthenticationReason::InvalidPairwiseCipher
            }
            DeauthenticationReasonMenu::InvalidAKMP => DeauthenticationReason::InvalidAKMP,
            DeauthenticationReasonMenu::UnsupportedRSNInformationElementVersion => {
                DeauthenticationReason::UnsupportedRSNInformationElementVersion
            }
            DeauthenticationReasonMenu::InvalidRSNInformationElementCapabilities => {
                DeauthenticationReason::InvalidRSNInformationElementCapabilities
            }
            DeauthenticationReasonMenu::IEEE8021XAuthenticationFailed => {
                DeauthenticationReason::IEEE8021XAuthenticationFailed
            }
            DeauthenticationReasonMenu::CipherSuiteRejectedBecauseOfSecurityPolicy => {
                DeauthenticationReason::CipherSuiteRejectedBecauseOfSecurityPolicy
            }
            DeauthenticationReasonMenu::TDLSUnreachable => DeauthenticationReason::TDLSUnreachable,
            DeauthenticationReasonMenu::TDLSUnspecifiedReason => {
                DeauthenticationReason::TDLSUnspecifiedReason
            }
            DeauthenticationReasonMenu::TDLSRejected => DeauthenticationReason::TDLSRejected,
            DeauthenticationReasonMenu::TDLSRequestedTearDown => {
                DeauthenticationReason::TDLSRequestedTearDown
            }
            DeauthenticationReasonMenu::TDLSChannelSwitching => {
                DeauthenticationReason::TDLSChannelSwitching
            }
            DeauthenticationReasonMenu::UnauthorizedAccessPoint => {
                DeauthenticationReason::UnauthorizedAccessPoint
            }
            DeauthenticationReasonMenu::PriorAuthenticationValid => {
                DeauthenticationReason::PriorAuthenticationValid
            }
            DeauthenticationReasonMenu::ExternalServiceRequirements => {
                DeauthenticationReason::ExternalServiceRequirements
            }
            DeauthenticationReasonMenu::InvalidFTActionFrameCount => {
                DeauthenticationReason::InvalidFTActionFrameCount
            }
            DeauthenticationReasonMenu::InvalidPMKID => DeauthenticationReason::InvalidPMKID,
            DeauthenticationReasonMenu::InvalidMDE => DeauthenticationReason::InvalidMDE,
            DeauthenticationReasonMenu::InvalidFTE => DeauthenticationReason::InvalidFTE,
            DeauthenticationReasonMenu::SMECancelsAuthentication => {
                DeauthenticationReason::SMECancelsAuthentication
            }
            DeauthenticationReasonMenu::PeerUnreachable => DeauthenticationReason::PeerUnreachable,
            DeauthenticationReasonMenu::PeerDeauthenticatedForListenIntervalTooLarge => {
                DeauthenticationReason::PeerDeauthenticatedForListenIntervalTooLarge
            }
            DeauthenticationReasonMenu::DisassociatedForReasonUnspecified => {
                DeauthenticationReason::DisassociatedForReasonUnspecified
            }
            DeauthenticationReasonMenu::PeerDeauthenticatedForReasonUnspecified => {
                DeauthenticationReason::PeerDeauthenticatedForReasonUnspecified
            }
            DeauthenticationReasonMenu::DisassociatedForSensorStation => {
                DeauthenticationReason::DisassociatedForSensorStation
            }
            DeauthenticationReasonMenu::DisassociatedForPoorChannelConditions => {
                DeauthenticationReason::DisassociatedForPoorChannelConditions
            }
            DeauthenticationReasonMenu::DisassociatedForBSSTransitionManagement => {
                DeauthenticationReason::DisassociatedForBSSTransitionManagement
            }
            DeauthenticationReasonMenu::DeauthenticatedForReasonUnspecified => {
                DeauthenticationReason::DeauthenticatedForReasonUnspecified
            }
            DeauthenticationReasonMenu::SessionInformationUnavailable => {
                DeauthenticationReason::SessionInformationUnavailable
            }
            DeauthenticationReasonMenu::DisassociatedForSCPRequestUnsuccessful => {
                DeauthenticationReason::DisassociatedForSCPRequestUnsuccessful
            }
            DeauthenticationReasonMenu::DeauthenticatedForSCPRequestUnsuccessful => {
                DeauthenticationReason::DeauthenticatedForSCPRequestUnsuccessful
            }
            DeauthenticationReasonMenu::DisassociatedDueToPoorRSSI => {
                DeauthenticationReason::DisassociatedDueToPoorRSSI
            }
        }
    }
}

impl fmt::Display for DeauthenticationReasonMenu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            DeauthenticationReasonMenu::PreviousAuthenticationNoLongerValid => {
                "PreviousAuthenticationNoLongerValid"
            }
            DeauthenticationReasonMenu::DeauthenticatedBecauseSTAIsLeaving => {
                "DeauthenticatedBecauseSTAIsLeaving"
            }
            DeauthenticationReasonMenu::DisassociatedDueToInactivity => {
                "DisassociatedDueToInactivity"
            }
            DeauthenticationReasonMenu::DisassociatedBecauseAPUnableToHandleAllSTAs => {
                "DisassociatedBecauseAPUnableToHandleAllSTAs"
            }
            DeauthenticationReasonMenu::Class2FrameReceivedFromNonauthenticatedSTA => {
                "Class2FrameReceivedFromNonauthenticatedSTA"
            }
            DeauthenticationReasonMenu::Class3FrameReceivedFromNonassociatedSTA => {
                "Class3FrameReceivedFromNonassociatedSTA"
            }
            DeauthenticationReasonMenu::DisassociatedBecauseSTALeavingBSS => {
                "DisassociatedBecauseSTALeavingBSS"
            }
            DeauthenticationReasonMenu::STARequestingReassociationNotAuthenticated => {
                "STARequestingReassociationNotAuthenticated"
            }
            DeauthenticationReasonMenu::DisassociatedBecauseOfPowerCapability => {
                "DisassociatedBecauseOfPowerCapability"
            }
            DeauthenticationReasonMenu::DisassociatedBecauseOfSupportedChannels => {
                "DisassociatedBecauseOfSupportedChannels"
            }
            DeauthenticationReasonMenu::InvalidInformationElement => "InvalidInformationElement",
            DeauthenticationReasonMenu::MICFailure => "MICFailure",
            DeauthenticationReasonMenu::FourWayHandshakeTimeout => "FourWayHandshakeTimeout",
            DeauthenticationReasonMenu::GroupKeyHandshakeTimeout => "GroupKeyHandshakeTimeout",
            DeauthenticationReasonMenu::InformationElementInFourWayHandshakeDifferent => {
                "InformationElementInFourWayHandshakeDifferent"
            }
            DeauthenticationReasonMenu::InvalidGroupCipher => "InvalidGroupCipher",
            DeauthenticationReasonMenu::InvalidPairwiseCipher => "InvalidPairwiseCipher",
            DeauthenticationReasonMenu::InvalidAKMP => "InvalidAKMP",
            DeauthenticationReasonMenu::UnsupportedRSNInformationElementVersion => {
                "UnsupportedRSNInformationElementVersion"
            }
            DeauthenticationReasonMenu::InvalidRSNInformationElementCapabilities => {
                "InvalidRSNInformationElementCapabilities"
            }
            DeauthenticationReasonMenu::IEEE8021XAuthenticationFailed => {
                "IEEE8021XAuthenticationFailed"
            }
            DeauthenticationReasonMenu::CipherSuiteRejectedBecauseOfSecurityPolicy => {
                "CipherSuiteRejectedBecauseOfSecurityPolicy"
            }
            DeauthenticationReasonMenu::TDLSUnreachable => "TDLSUnreachable",
            DeauthenticationReasonMenu::TDLSUnspecifiedReason => "TDLSUnspecifiedReason",
            DeauthenticationReasonMenu::TDLSRejected => "TDLSRejected",
            DeauthenticationReasonMenu::TDLSRequestedTearDown => "TDLSRequestedTearDown",
            DeauthenticationReasonMenu::TDLSChannelSwitching => "TDLSChannelSwitching",
            DeauthenticationReasonMenu::UnauthorizedAccessPoint => "UnauthorizedAccessPoint",
            DeauthenticationReasonMenu::PriorAuthenticationValid => "PriorAuthenticationValid",
            DeauthenticationReasonMenu::ExternalServiceRequirements => {
                "ExternalServiceRequirements"
            }
            DeauthenticationReasonMenu::InvalidFTActionFrameCount => "InvalidFTActionFrameCount",
            DeauthenticationReasonMenu::InvalidPMKID => "InvalidPMKID",
            DeauthenticationReasonMenu::InvalidMDE => "InvalidMDE",
            DeauthenticationReasonMenu::InvalidFTE => "InvalidFTE",
            DeauthenticationReasonMenu::SMECancelsAuthentication => "SMECancelsAuthentication",
            DeauthenticationReasonMenu::PeerUnreachable => "PeerUnreachable",
            DeauthenticationReasonMenu::PeerDeauthenticatedForListenIntervalTooLarge => {
                "PeerDeauthenticatedForListenIntervalTooLarge"
            }
            DeauthenticationReasonMenu::DisassociatedForReasonUnspecified => {
                "DisassociatedForReasonUnspecified"
            }
            DeauthenticationReasonMenu::PeerDeauthenticatedForReasonUnspecified => {
                "PeerDeauthenticatedForReasonUnspecified"
            }
            DeauthenticationReasonMenu::DisassociatedForSensorStation => {
                "DisassociatedForSensorStation"
            }
            DeauthenticationReasonMenu::DisassociatedForPoorChannelConditions => {
                "DisassociatedForPoorChannelConditions"
            }
            DeauthenticationReasonMenu::DisassociatedForBSSTransitionManagement => {
                "DisassociatedForBSSTransitionManagement"
            }
            DeauthenticationReasonMenu::DeauthenticatedForReasonUnspecified => {
                "DeauthenticatedForReasonUnspecified"
            }
            DeauthenticationReasonMenu::SessionInformationUnavailable => {
                "SessionInformationUnavailable"
            }
            DeauthenticationReasonMenu::DisassociatedForSCPRequestUnsuccessful => {
                "DisassociatedForSCPRequestUnsuccessful"
            }
            DeauthenticationReasonMenu::DeauthenticatedForSCPRequestUnsuccessful => {
                "DeauthenticatedForSCPRequestUnsuccessful"
            }
            DeauthenticationReasonMenu::DisassociatedDueToPoorRSSI => "DisassociatedDueToPoorRSSI",
        };
        write!(f, "[{}] {}", self.to_reason() as u8, name)
    }
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
            71 => DeauthenticationReason::DisassociatedDueToPoorRSSI,
            _ => DeauthenticationReason::Unknown,
        }
    }
}
