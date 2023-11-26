use neli::attr::AttrHandle;
use neli::consts::genl::NlAttrType;
use neli::genl::Nlattr;
use neli::types::{Buffer, GenlBuffer};
use neli_proc_macros::neli_enum;

pub type Attrs<'a, T> = AttrHandle<'a, GenlBuffer<T, Buffer>, Nlattr<T, Buffer>>;

#[neli_enum(serialized_type = "u16")]
pub enum NlaNested {
    Unspec = 0,
}

impl NlAttrType for NlaNested {}

/// nl80211Attrs
///
/// Enumeration from nl80211/nl80211.h:1929
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211Attr {
    AttrUnspec = 0,
    AttrWiphy = 1,
    AttrWiphyName = 2,
    AttrIfindex = 3,
    AttrIfname = 4,
    AttrIftype = 5,
    AttrMac = 6,
    AttrKeyData = 7,
    AttrKeyIdx = 8,
    AttrKeyCipher = 9,
    AttrKeySeq = 10,
    AttrKeyDefault = 11,
    AttrBeaconInterval = 12,
    AttrDtimPeriod = 13,
    AttrBeaconHead = 14,
    AttrBeaconTail = 15,
    AttrStaAid = 16,
    AttrStaFlags = 17,
    AttrStaListenInterval = 18,
    AttrStaSupportedRates = 19,
    AttrStaVlan = 20,
    AttrStaInfo = 21,
    AttrWiphyBands = 22,
    AttrMntrFlags = 23,
    AttrMeshId = 24,
    AttrStaPlinkAction = 25,
    AttrMpathNextHop = 26,
    AttrMpathInfo = 27,
    AttrBssCtsProt = 28,
    AttrBssShortPreamble = 29,
    AttrBssShortSlotTime = 30,
    AttrHtCapability = 31,
    AttrSupportedIftypes = 32,
    AttrRegAlpha2 = 33,
    AttrRegRules = 34,
    AttrMeshConfig = 35,
    AttrBssBasicRates = 36,
    AttrWiphyTxqParams = 37,
    AttrWiphyFreq = 38,
    AttrWiphyChannelType = 39,
    AttrKeyDefaultMgmt = 40,
    AttrMgmtSubtype = 41,
    AttrIe = 42,
    AttrMaxNumScanSsids = 43,
    AttrScanFrequencies = 44,
    AttrScanSsids = 45,
    AttrGeneration = 46,
    AttrBss = 47,
    AttrRegInitiator = 48,
    AttrRegType = 49,
    AttrSupportedCommands = 50,
    AttrFrame = 51,
    AttrSsid = 52,
    AttrAuthType = 53,
    AttrReasonCode = 54,
    AttrKeyType = 55,
    AttrMaxScanIeLen = 56,
    AttrCipherSuites = 57,
    AttrFreqBefore = 58,
    AttrFreqAfter = 59,
    AttrFreqFixed = 60,
    AttrWiphyRetryShort = 61,
    AttrWiphyRetryLong = 62,
    AttrWiphyFragThreshold = 63,
    AttrWiphyRtsThreshold = 64,
    AttrTimedOut = 65,
    AttrUseMfp = 66,
    AttrStaFlags2 = 67,
    AttrControlPort = 68,
    AttrTestdata = 69,
    AttrPrivacy = 70,
    AttrDisconnectedByAp = 71,
    AttrStatusCode = 72,
    AttrCipherSuitesPairwise = 73,
    AttrCipherSuiteGroup = 74,
    AttrWpaVersions = 75,
    AttrAkmSuites = 76,
    AttrReqIe = 77,
    AttrRespIe = 78,
    AttrPrevBssid = 79,
    AttrKey = 80,
    AttrKeys = 81,
    AttrPid = 82,
    Attr4addr = 83,
    AttrSurveyInfo = 84,
    AttrPmkid = 85,
    AttrMaxNumPmkids = 86,
    AttrDuration = 87,
    AttrCookie = 88,
    AttrWiphyCoverageClass = 89,
    AttrTxRates = 90,
    AttrFrameMatch = 91,
    AttrAck = 92,
    AttrPsState = 93,
    AttrCqm = 94,
    AttrLocalStateChange = 95,
    AttrApIsolate = 96,
    AttrWiphyTxPowerSetting = 97,
    AttrWiphyTxPowerLevel = 98,
    AttrTxFrameTypes = 99,
    AttrRxFrameTypes = 100,
    AttrFrameType = 101,
    AttrControlPortEthertype = 102,
    AttrControlPortNoEncrypt = 103,
    AttrSupportIbssRsn = 104,
    AttrWiphyAntennaTx = 105,
    AttrWiphyAntennaRx = 106,
    AttrMcastRate = 107,
    AttrOffchannelTxOk = 108,
    AttrBssHtOpmode = 109,
    AttrKeyDefaultTypes = 110,
    AttrMaxRemainOnChannelDuration = 111,
    AttrMeshSetup = 112,
    AttrWiphyAntennaAvailTx = 113,
    AttrWiphyAntennaAvailRx = 114,
    AttrSupportMeshAuth = 115,
    AttrStaPlinkState = 116,
    AttrWowlanTriggers = 117,
    AttrWowlanTriggersSupported = 118,
    AttrSchedScanInterval = 119,
    AttrInterfaceCombinations = 120,
    AttrSoftwareIftypes = 121,
    AttrRekeyData = 122,
    AttrMaxNumSchedScanSsids = 123,
    AttrMaxSchedScanIeLen = 124,
    AttrScanSuppRates = 125,
    AttrHiddenSsid = 126,
    AttrIeProbeResp = 127,
    AttrIeAssocResp = 128,
    AttrStaWme = 129,
    AttrSupportApUapsd = 130,
    AttrRoamSupport = 131,
    AttrSchedScanMatch = 132,
    AttrMaxMatchSets = 133,
    AttrPmksaCandidate = 134,
    AttrTxNoCckRate = 135,
    AttrTdlsAction = 136,
    AttrTdlsDialogToken = 137,
    AttrTdlsOperation = 138,
    AttrTdlsSupport = 139,
    AttrTdlsExternalSetup = 140,
    AttrDeviceApSme = 141,
    AttrDontWaitForAck = 142,
    AttrFeatureFlags = 143,
    AttrProbeRespOffload = 144,
    AttrProbeResp = 145,
    AttrDfsRegion = 146,
    AttrDisableHt = 147,
    AttrHtCapabilityMask = 148,
    AttrNoackMap = 149,
    AttrInactivityTimeout = 150,
    AttrRxSignalDbm = 151,
    AttrBgScanPeriod = 152,
    AttrWdev = 153,
    AttrUserRegHintType = 154,
    AttrConnFailedReason = 155,
    AttrSaeData = 156,
    AttrVhtCapability = 157,
    AttrScanFlags = 158,
    AttrChannelWidth = 159,
    AttrCenterFreq1 = 160,
    AttrCenterFreq2 = 161,
    AttrP2pCtwindow = 162,
    AttrP2pOppps = 163,
    AttrLocalMeshPowerMode = 164,
    AttrAclPolicy = 165,
    AttrMacAddrs = 166,
    AttrMacAclMax = 167,
    AttrRadarEvent = 168,
    AttrExtCapa = 169,
    AttrExtCapaMask = 170,
    AttrStaCapability = 171,
    AttrStaExtCapability = 172,
    AttrProtocolFeatures = 173,
    AttrSplitWiphyDump = 174,
    AttrDisableVht = 175,
    AttrVhtCapabilityMask = 176,
    AttrMdid = 177,
    AttrIeRic = 178,
    AttrCritProtId = 179,
    AttrMaxCritProtDuration = 180,
    AttrPeerAid = 181,
    AttrCoalesceRule = 182,
    AttrChSwitchCount = 183,
    AttrChSwitchBlockTx = 184,
    AttrCsaIes = 185,
    AttrCsaCOffBeacon = 186,
    AttrCsaCOffPresp = 187,
    AttrRxmgmtFlags = 188,
    AttrStaSupportedChannels = 189,
    AttrStaSupportedOperClasses = 190,
    AttrHandleDfs = 191,
    AttrSupport5Mhz = 192,
    AttrSupport10Mhz = 193,
    AttrOpmodeNotif = 194,
    AttrVendorId = 195,
    AttrVendorSubcmd = 196,
    AttrVendorData = 197,
    AttrVendorEvents = 198,
    AttrQosMap = 199,
    AttrMacHint = 200,
    AttrWiphyFreqHint = 201,
    AttrMaxApAssocSta = 202,
    AttrTdlsPeerCapability = 203,
    AttrSocketOwner = 204,
    AttrCsaCOffsetsTx = 205,
    AttrMaxCsaCounters = 206,
    AttrTdlsInitiator = 207,
    AttrUseRrm = 208,
    AttrWiphyDynAck = 209,
    AttrTsid = 210,
    AttrUserPrio = 211,
    AttrAdmittedTime = 212,
    AttrSmpsMode = 213,
    AttrOperClass = 214,
    AttrMacMask = 215,
    AttrWiphySelfManagedReg = 216,
    AttrExtFeatures = 217,
    AttrSurveyRadioStats = 218,
    AttrNetnsFd = 219,
    AttrSchedScanDelay = 220,
    AttrRegIndoor = 221,
    AttrMaxNumSchedScanPlans = 222,
    AttrMaxScanPlanInterval = 223,
    AttrMaxScanPlanIterations = 224,
    AttrSchedScanPlans = 225,
    AttrPbss = 226,
    AttrBssSelect = 227,
    AttrStaSupportP2pPs = 228,
    AttrPad = 229,
    AttrIftypeExtCapa = 230,
    AttrMuMimoGroupData = 231,
    AttrMuMimoFollowMacAddr = 232,
    AttrScanStartTimeTsf = 233,
    AttrScanStartTimeTsfBssid = 234,
    AttrMeasurementDuration = 235,
    AttrMeasurementDurationMandatory = 236,
    AttrMeshPeerAid = 237,
    AttrNanMasterPref = 238,
    AttrNanDual = 239,
    AttrNanFunc = 240,
    AttrNanMatch = 241,
}

impl NlAttrType for Nl80211Attr {}

/// nl80211Iftype
///
/// Enumeration from nl80211/nl80211.h:2384
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211Iftype {
    IftypeUnspecified = 0,
    IftypeAdhoc = 1,
    IftypeStation = 2,
    IftypeAp = 3,
    IftypeApVlan = 4,
    IftypeWds = 5,
    IftypeMonitor = 6,
    IftypeMeshPoint = 7,
    IftypeP2pClient = 8,
    IftypeP2pGo = 9,
    IftypeP2pDevice = 10,
    IftypeOcb = 11,
    IftypeNan = 12,
}

impl NlAttrType for Nl80211Iftype {}

impl Nl80211Iftype {
    pub fn from_u8(n: u8) -> Option<Nl80211Iftype> {
        match n {
            0 => Some(Nl80211Iftype::IftypeUnspecified),
            1 => Some(Nl80211Iftype::IftypeAdhoc),
            2 => Some(Nl80211Iftype::IftypeStation),
            3 => Some(Nl80211Iftype::IftypeAp),
            4 => Some(Nl80211Iftype::IftypeApVlan),
            5 => Some(Nl80211Iftype::IftypeWds),
            6 => Some(Nl80211Iftype::IftypeMonitor),
            7 => Some(Nl80211Iftype::IftypeMeshPoint),
            8 => Some(Nl80211Iftype::IftypeP2pClient),
            9 => Some(Nl80211Iftype::IftypeP2pGo),
            10 => Some(Nl80211Iftype::IftypeP2pDevice),
            11 => Some(Nl80211Iftype::IftypeOcb),
            12 => Some(Nl80211Iftype::IftypeNan),
            _ => None, // Handle unknown values
        }
    }

    pub fn string(&self) -> &str {
        match *self {
            Nl80211Iftype::IftypeUnspecified => "Unspecified",
            Nl80211Iftype::IftypeAdhoc => "Adhoc",
            Nl80211Iftype::IftypeStation => "Station",
            Nl80211Iftype::IftypeAp => "Ap",
            Nl80211Iftype::IftypeApVlan => "ApVlan",
            Nl80211Iftype::IftypeWds => "Wds",
            Nl80211Iftype::IftypeMonitor => "Monitor",
            Nl80211Iftype::IftypeMeshPoint => "MeshPoint",
            Nl80211Iftype::IftypeP2pClient => "P2P Client",
            Nl80211Iftype::IftypeP2pGo => "P2P Go",
            Nl80211Iftype::IftypeP2pDevice => "P2P Device",
            Nl80211Iftype::IftypeOcb => "OCB",
            Nl80211Iftype::IftypeNan => "NAN",
            _ => "Unknown",
        }
    }
}

/// nl80211StaFlags as declared in nl80211/nl80211.h:2428
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211StaFlags {
    StaFlagInvalid = 0,
    StaFlagAuthorized = 1,
    StaFlagShortPreamble = 2,
    StaFlagWme = 3,
    StaFlagMfp = 4,
    StaFlagAuthenticated = 5,
    StaFlagTdlsPeer = 6,
    StaFlagAssociated = 7,
}

impl NlAttrType for Nl80211StaFlags {}

/// nl80211StaP2pPsStatus
///
/// Enumeration from nl80211/nl80211.h:2450
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211StaP2pPsStatus {
    P2pPsUnsupported = 0,
    P2pPsSupported = 1,
}

impl NlAttrType for Nl80211StaP2pPsStatus {}

/// nl80211RateInfo
///
/// Enumeration from nl80211/nl80211.h:2505
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211RateInfo {
    RateInfoInvalid = 0,
    RateInfoBitrate = 1,
    RateInfoMcs = 2,
    RateInfo40MhzWidth = 3,
    RateInfoShortGi = 4,
    RateInfoBitrate32 = 5,
    RateInfoVhtMcs = 6,
    RateInfoVhtNss = 7,
    RateInfo80MhzWidth = 8,
    RateInfo80p80MhzWidth = 9,
    RateInfo160MhzWidth = 10,
    RateInfo10MhzWidth = 11,
    RateInfo5MhzWidth = 12,
}

impl NlAttrType for Nl80211RateInfo {}

/// nl80211StaBssParam
///
/// Enumeration from nl80211/nl80211.h:2542
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211StaBssParam {
    StaBssParamInvalid = 0,
    StaBssParamCtsProt = 1,
    StaBssParamShortPreamble = 2,
    StaBssParamShortSlotTime = 3,
    StaBssParamDtimPeriod = 4,
    StaBssParamBeaconInterval = 5,
}

impl NlAttrType for Nl80211StaBssParam {}

/// nl80211StaInfo
///
/// Enumeration from nl80211/nl80211.h:2620
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211StaInfo {
    StaInfoInvalid = 0,
    StaInfoInactiveTime = 1,
    StaInfoRxBytes = 2,
    StaInfoTxBytes = 3,
    StaInfoLlid = 4,
    StaInfoPlid = 5,
    StaInfoPlinkState = 6,
    StaInfoSignal = 7,
    StaInfoTxBitrate = 8,
    StaInfoRxPackets = 9,
    StaInfoTxPackets = 10,
    StaInfoTxRetries = 11,
    StaInfoTxFailed = 12,
    StaInfoSignalAvg = 13,
    StaInfoRxBitrate = 14,
    StaInfoBssParam = 15,
    StaInfoConnectedTime = 16,
    StaInfoStaFlags = 17,
    StaInfoBeaconLoss = 18,
    StaInfoTOffset = 19,
    StaInfoLocalPm = 20,
    StaInfoPeerPm = 21,
    StaInfoNonpeerPm = 22,
    StaInfoRxBytes64 = 23,
    StaInfoTxBytes64 = 24,
    StaInfoChainSignal = 25,
    StaInfoChainSignalAvg = 26,
    StaInfoExpectedThroughput = 27,
    StaInfoRxDropMisc = 28,
    StaInfoBeaconRx = 29,
    StaInfoBeaconSignalAvg = 30,
    StaInfoTidStats = 31,
    StaInfoRxDuration = 32,
    StaInfoPad = 33,
}

impl NlAttrType for Nl80211StaInfo {}

/// nl80211TidStats
///
/// Enumeration from nl80211/nl80211.h:2675
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211TidStats {
    TidStatsInvalid = 0,
    TidStatsRxMsdu = 1,
    TidStatsTxMsdu = 2,
    TidStatsTxMsduRetries = 3,
    TidStatsTxMsduFailed = 4,
    TidStatsPad = 5,
}

impl NlAttrType for Nl80211TidStats {}

/// nl80211MpathFlags
///
/// Enumeration from nl80211/nl80211.h:2697
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211MpathFlags {
    MpathFlagActive = 1 << 0,
    MpathFlagResolving = 1 << 1,
    MpathFlagSnValid = 1 << 2,
    MpathFlagFixed = 1 << 3,
    MpathFlagResolved = 1 << 4,
}

impl NlAttrType for Nl80211MpathFlags {}

/// nl80211MpathFlags
///
/// Enumeration from nl80211/nl80211.h:2697
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211MpathInfo {
    MpathInfoInvalid = 0,
    MpathInfoFrameQlen = 1,
    MpathInfoSn = 2,
    MpathInfoMetric = 3,
    MpathInfoExptime = 4,
    MpathInfoFlags = 5,
    MpathInfoDiscoveryTimeout = 6,
    MpathInfoDiscoveryRetries = 7,
}

impl NlAttrType for Nl80211MpathInfo {}

/// nl80211BandAttr
///
/// Enumeration from nl80211/nl80211.h:2757
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211BandAttr {
    BandAttrInvalid = 0,
    BandAttrFreqs = 1,
    BandAttrRates = 2,
    BandAttrHtMcsSet = 3,
    BandAttrHtCapa = 4,
    BandAttrHtAmpduFactor = 5,
    BandAttrHtAmpduDensity = 6,
    BandAttrVhtMcsSet = 7,
    BandAttrVhtCapa = 8,
}

impl NlAttrType for Nl80211BandAttr {}

/// nl80211FrequencyAttr
///
/// Enumeration from nl80211/nl80211.h:2833
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211FrequencyAttr {
    FrequencyAttrInvalid = 0,
    FrequencyAttrFreq = 1,
    FrequencyAttrDisabled = 2,
    FrequencyAttrNoIr = 3,
    FrequencyAttrNoIbss = 4,
    FrequencyAttrRadar = 5,
    FrequencyAttrMaxTxPower = 6,
    FrequencyAttrDfsState = 7,
    FrequencyAttrDfsTime = 8,
    FrequencyAttrNoHt40Minus = 9,
    FrequencyAttrNoHt40Plus = 10,
    FrequencyAttrNo80mhz = 11,
    FrequencyAttrNo160mhz = 12,
    FrequencyAttrDfsCacTime = 13,
    FrequencyAttrIndoorOnly = 14,
    FrequencyAttrIrConcurrent = 15,
    FrequencyAttrNo20mhz = 16,
    FrequencyAttrNo10mhz = 17,
}

impl NlAttrType for Nl80211FrequencyAttr {}

/// nl80211BitrateAttr
///
/// Enumeration from nl80211/nl80211.h:2873
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211BitrateAttr {
    BitrateAttrInvalid = 0,
    BitrateAttrRate = 1,
    BitrateAttr2ghzShortpreamble = 2,
}

impl NlAttrType for Nl80211BitrateAttr {}

/// nl80211RegInitiator
///
/// Enumeration from nl80211/nl80211.h:2899
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211RegInitiator {
    RegdomSetByCore = 0,
    RegdomSetByUser = 1,
    RegdomSetByDriver = 2,
    RegdomSetByCountryIe = 3,
}

impl NlAttrType for Nl80211RegInitiator {}

/// nl80211RegType
///
/// Enumeration from nl80211/nl80211.h:2922
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211RegType {
    RegdomTypeCountry = 0,
    RegdomTypeWorld = 1,
    RegdomTypeCustomWorld = 2,
    RegdomTypeIntersection = 3,
}

impl NlAttrType for Nl80211RegType {}

/// nl80211RegRuleAttr
///
/// Enumeration from nl80211/nl80211.h:2954
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211RegRuleAttr {
    RegRuleAttrInvalid = 0,
    AttrRegRuleFlags = 1,
    AttrFreqRangeStart = 2,
    AttrFreqRangeEnd = 3,
    AttrFreqRangeMaxBw = 4,
    AttrPowerRuleMaxAntGain = 5,
    AttrPowerRuleMaxEirp = 6,
    AttrDfsCacTime = 7,
}

impl NlAttrType for Nl80211RegRuleAttr {}

/// nl80211SchedScanMatchAttr
///
/// Enumeration from nl80211/nl80211.h:2989
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211SchedScanMatchAttr {
    SchedScanMatchAttrInvalid = 0,
    SchedScanMatchAttrSsid = 1,
    SchedScanMatchAttrRssi = 2,
}

impl NlAttrType for Nl80211SchedScanMatchAttr {}

/// nl80211RegRuleFlags
///
/// Enumeration from nl80211/nl80211.h:3026
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211RegRuleFlags {
    RrfNoOfdm = 1 << 0,
    RrfNoCck = 1 << 1,
    RrfNoIndoor = 1 << 2,
    RrfNoOutdoor = 1 << 3,
    RrfDfs = 1 << 4,
    RrfPtpOnly = 1 << 5,
    RrfPtmpOnly = 1 << 6,
    RrfNoIr = 1 << 7,
    RrfNoIbss = 1 << 8,
    RrfAutoBw = 1 << 11,
    RrfIrConcurrent = 1 << 12,
    RrfNoHt40minus = 1 << 13,
    RrfNoHt40plus = 1 << 14,
    RrfNo80mhz = 1 << 15, // RrfNo160mhz  =1 << 16
}

impl NlAttrType for Nl80211RegRuleFlags {}

/// nl80211DfsRegions
///
/// Enumeration from nl80211/nl80211.h:3061
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211DfsRegions {
    DfsUnset = 0,
    DfsFcc = 1,
    DfsEtsi = 2,
    DfsJp = 3,
}

impl NlAttrType for Nl80211DfsRegions {}

/// nl80211UserRegHintType
///
/// Enumeration from nl80211/nl80211.h:3085
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211UserRegHintType {
    UserRegHintUser = 0,
    UserRegHintCellBase = 1,
    UserRegHintIndoor = 2,
}

impl NlAttrType for Nl80211UserRegHintType {}

/// nl80211SurveyInfo
///
/// Enumeration from nl80211/nl80211.h:3118
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211SurveyInfo {
    SurveyInfoInvalid = 0,
    SurveyInfoFrequency = 1,
    SurveyInfoNoise = 2,
    SurveyInfoInUse = 3,
    SurveyInfoTime = 4,
    SurveyInfoTimeBusy = 5,
    SurveyInfoTimeExtBusy = 6,
    SurveyInfoTimeRx = 7,
    SurveyInfoTimeTx = 8,
    SurveyInfoTimeScan = 9,
    SurveyInfoPad = 10,
}

impl NlAttrType for Nl80211SurveyInfo {}

/// nl80211MntrFlags
///
/// Enumeration from nl80211/nl80211.h:3162
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211MntrFlags {
    MntrFlagInvalid = 0,
    MntrFlagFcsfail = 1,
    MntrFlagPlcpfail = 2,
    MntrFlagControl = 3,
    MntrFlagOtherBss = 4,
    MntrFlagCookFrames = 5,
    MntrFlagActive = 6,
}

impl NlAttrType for Nl80211MntrFlags {}

/// nl80211MeshPowerMode
///
/// Enumeration from nl80211/nl80211.h:3194
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211MeshPowerMode {
    MeshPowerUnknown = 0,
    MeshPowerActive = 1,
    MeshPowerLightSleep = 2,
    MeshPowerDeepSleep = 3,
}

impl NlAttrType for Nl80211MeshPowerMode {}

/// nl80211MeshconfParams
///
/// Enumeration from nl80211/nl80211.h:3312
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211MeshconfParams {
    MeshconfInvalid = 0,
    MeshconfRetryTimeout = 1,
    MeshconfConfirmTimeout = 2,
    MeshconfHoldingTimeout = 3,
    MeshconfMaxPeerLinks = 4,
    MeshconfMaxRetries = 5,
    MeshconfTtl = 6,
    MeshconfAutoOpenPlinks = 7,
    MeshconfHwmpMaxPreqRetries = 8,
    MeshconfPathRefreshTime = 9,
    MeshconfMinDiscoveryTimeout = 10,
    MeshconfHwmpActivePathTimeout = 11,
    MeshconfHwmpPreqMinInterval = 12,
    MeshconfHwmpNetDiamTrvsTime = 13,
    MeshconfHwmpRootmode = 14,
    MeshconfElementTtl = 15,
    MeshconfHwmpRannInterval = 16,
    MeshconfGateAnnouncements = 17,
    MeshconfHwmpPerrMinInterval = 18,
    MeshconfForwarding = 19,
    MeshconfRssiThreshold = 20,
    MeshconfSyncOffsetMaxNeighbor = 21,
    MeshconfHtOpmode = 22,
    MeshconfHwmpPathToRootTimeout = 23,
    MeshconfHwmpRootInterval = 24,
    MeshconfHwmpConfirmationInterval = 25,
    MeshconfPowerMode = 26,
    MeshconfAwakeWindow = 27,
    MeshconfPlinkTimeout = 28,
}

impl NlAttrType for Nl80211MeshconfParams {}

/// nl80211MeshSetupParams
///
/// Enumeration from nl80211/nl80211.h:3397
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211MeshSetupParams {
    MeshSetupInvalid = 0,
    MeshSetupEnableVendorPathSel = 1,
    MeshSetupEnableVendorMetric = 2,
    MeshSetupIe = 3,
    MeshSetupUserspaceAuth = 4,
    MeshSetupUserspaceAmpe = 5,
    MeshSetupEnableVendorSync = 6,
    MeshSetupUserspaceMpm = 7,
    MeshSetupAuthProtocol = 8,
}

impl NlAttrType for Nl80211MeshSetupParams {}

/// nl80211TxqAttr
///
/// Enumeration from nl80211/nl80211.h:3427
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211TxqAttr {
    TxqAttrInvalid = 0,
    TxqAttrAc = 1,
    TxqAttrTxop = 2,
    TxqAttrCwmin = 3,
    TxqAttrCwmax = 4,
    TxqAttrAifs = 5,
}

impl NlAttrType for Nl80211TxqAttr {}

/// nl80211Ac
///
/// Enumeration from nl80211/nl80211.h:3440
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211Ac {
    AcVo = 0,
    AcVi = 1,
    AcBe = 2,
    AcBk = 3,
}

impl NlAttrType for Nl80211Ac {}

/// nl80211ChannelType
///
/// Enumeration from nl80211/nl80211.h:3464
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211ChannelType {
    ChanNoHt = 0,
    ChanHt20 = 1,
    ChanHt40minus = 2,
    ChanHt40plus = 3,
}

impl NlAttrType for Nl80211ChannelType {}

/// nl80211ChanWidth
///
/// Enumeration from nl80211/nl80211.h:3490
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211ChanWidth {
    ChanWidth20Noht = 0,
    ChanWidth20 = 1,
    ChanWidth40 = 2,
    ChanWidth80 = 3,
    ChanWidth80p80 = 4,
    ChanWidth160 = 5,
    ChanWidth5 = 6,
    ChanWidth10 = 7,
}

impl NlAttrType for Nl80211ChanWidth {}

/// nl80211BssScanWidth
///
/// Enumeration from nl80211/nl80211.h:3510
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211BssScanWidth {
    BssChanWidth20 = 0,
    BssChanWidth10 = 1,
    BssChanWidth5 = 2,
}

impl NlAttrType for Nl80211BssScanWidth {}

/// nl80211Bss
///
/// Enumeration from nl80211/nl80211.h:3565
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211Bss {
    BssInvalid = 0,
    BssBssid = 1,
    BssFrequency = 2,
    BssTsf = 3,
    BssBeaconInterval = 4,
    BssCapability = 5,
    BssInformationElements = 6,
    BssSignalMbm = 7,
    BssSignalUnspec = 8,
    BssStatus = 9,
    BssSeenMsAgo = 10,
    BssBeaconIes = 11,
    BssChanWidth = 12,
    BssBeaconTsf = 13,
    BssPrespData = 14,
    BssLastSeenBoottime = 15,
    BssPad = 16,
    BssParentTsf = 17,
    BssParentBssid = 18,
}

impl NlAttrType for Nl80211Bss {}

/// nl80211BssStatus
///
/// Enumeration from nl80211/nl80211.h:3603
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211BssStatus {
    BssStatusAuthenticated = 0,
    BssStatusAssociated = 1,
    BssStatusIbssJoined = 2,
}

impl NlAttrType for Nl80211BssStatus {}

/// nl80211AuthType
///
/// Enumeration from nl80211/nl80211.h:3623
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211AuthType {
    AuthtypeOpenSystem = 0,
    AuthtypeSharedKey = 1,
    AuthtypeFt = 2,
    AuthtypeNetworkEap = 3,
    AuthtypeSae = 4,
    AuthtypeNum = 5,
    AuthtypeMax = 4,
    AuthtypeAutomatic = 5,
}

impl NlAttrType for Nl80211AuthType {}

/// nl80211KeyType
///
/// Enumeration from nl80211/nl80211.h:3643
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211KeyType {
    KeytypeGroup = 0,
    KeytypePairwise = 1,
    KeytypePeerkey = 2,
}

impl NlAttrType for Nl80211KeyType {}

/// nl80211Mfp
///
/// Enumeration from nl80211/nl80211.h:3656
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211Mfp {
    MfpNo = 0,
    MfpRequired = 1,
}

impl NlAttrType for Nl80211Mfp {}

/// nl80211WpaVersions
///
/// Enumeration from nl80211/nl80211.h:3661
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211WpaVersions {
    WpaVersion1 = 1 << 0,
    WpaVersion2 = 1 << 1,
}

impl NlAttrType for Nl80211WpaVersions {}

/// nl80211KeyDefaultTypes
///
/// Enumeration from nl80211/nl80211.h:3675
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211KeyDefaultTypes {
    KeyDefaultTypeInvalid = 0,
    KeyDefaultTypeUnicast = 1,
    KeyDefaultTypeMulticast = 2,
}

impl NlAttrType for Nl80211KeyDefaultTypes {}

/// nl80211KeyAttributes
///
/// Enumeration from nl80211/nl80211.h:3705
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211KeyAttributes {
    KeyInvalid = 0,
    KeyData = 1,
    KeyIdx = 2,
    KeyCipher = 3,
    KeySeq = 4,
    KeyDefault = 5,
    KeyDefaultMgmt = 6,
    KeyType = 7,
    KeyDefaultTypes = 8,
}

impl NlAttrType for Nl80211KeyAttributes {}

/// nl80211TxRateAttributes
///
/// Enumeration from nl80211/nl80211.h:3736
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211TxRateAttributes {
    TxrateInvalid = 0,
    TxrateLegacy = 1,
    TxrateHt = 2,
    TxrateVht = 3,
    TxrateGi = 4,
}

impl NlAttrType for Nl80211TxRateAttributes {}

/// nl80211TxrateGi
///
/// Enumeration from nl80211/nl80211.h:3759
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211TxrateGi {
    TxrateDefaultGi = 0,
    TxrateForceSgi = 1,
    TxrateForceLgi = 2,
}

impl NlAttrType for Nl80211TxrateGi {}

/// nl80211Band
///
/// Enumeration from nl80211/nl80211.h:3773
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211Bandc {
    Band2ghz = 0,
    Band5ghz = 1,
    Band60ghz = 2,
}

impl NlAttrType for Nl80211Bandc {}

/// nl80211PsState
///
/// Enumeration from nl80211/nl80211.h:3786
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211PsState {
    PsDisabled = 0,
    PsEnabled = 1,
}

impl NlAttrType for Nl80211PsState {}

/// nl80211AttrCqm
///
/// Enumeration from nl80211/nl80211.h:3819
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211AttrCqm {
    AttrCqmInvalid = 0,
    AttrCqmRssiThold = 1,
    AttrCqmRssiHyst = 2,
    AttrCqmRssiThresholdEvent = 3,
    AttrCqmPktLossEvent = 4,
    AttrCqmTxeRate = 5,
    AttrCqmTxePkts = 6,
    AttrCqmTxeIntvl = 7,
    AttrCqmBeaconLossEvent = 8,
}

impl NlAttrType for Nl80211AttrCqm {}

/// nl80211CqmRssiThresholdEvent
///
/// Enumeration from nl80211/nl80211.h:3843
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211CqmRssiThresholdEvent {
    CqmRssiThresholdEventLow = 0,
    CqmRssiThresholdEventHigh = 1,
    CqmRssiBeaconLossEvent = 2,
}

impl NlAttrType for Nl80211CqmRssiThresholdEvent {}

/// nl80211TxPowerSetting
///
/// Enumeration from nl80211/nl80211.h:3856
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211TxPowerSetting {
    TxPowerAutomatic = 0,
    TxPowerLimited = 1,
    TxPowerFixed = 2,
}

impl NlAttrType for Nl80211TxPowerSetting {}

/// nl80211PacketPatternAttr
///
/// Enumeration from nl80211/nl80211.h:3883
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211PacketPatternAttr {
    PktpatInvalid = 0,
    PktpatMask = 1,
    PktpatPattern = 2,
    PktpatOffset = 3,
}

impl NlAttrType for Nl80211PacketPatternAttr {}

/// nl80211WowlanTriggers
///
/// Enumeration from nl80211/nl80211.h:4011
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211WowlanTriggers {
    WowlanTrigInvalid = 0,
    WowlanTrigAny = 1,
    WowlanTrigDisconnect = 2,
    WowlanTrigMagicPkt = 3,
    WowlanTrigPktPattern = 4,
    WowlanTrigGtkRekeySupported = 5,
    WowlanTrigGtkRekeyFailure = 6,
    WowlanTrigEapIdentRequest = 7,
    WowlanTrig4wayHandshake = 8,
    WowlanTrigRfkillRelease = 9,
    WowlanTrigWakeupPkt80211 = 10,
    WowlanTrigWakeupPkt80211Len = 11,
    WowlanTrigWakeupPkt8023 = 12,
    WowlanTrigWakeupPkt8023Len = 13,
    WowlanTrigTcpConnection = 14,
    WowlanTrigWakeupTcpMatch = 15,
    WowlanTrigWakeupTcpConnlost = 16,
    WowlanTrigWakeupTcpNomoretokens = 17,
    WowlanTrigNetDetect = 18,
    WowlanTrigNetDetectResults = 19,
}

impl NlAttrType for Nl80211WowlanTriggers {}

/// nl80211WowlanTcpAttrs
///
/// Enumeration from nl80211/nl80211.h:4129
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211WowlanTcpAttrs {
    WowlanTcpInvalid = 0,
    WowlanTcpSrcIpv4 = 1,
    WowlanTcpDstIpv4 = 2,
    WowlanTcpDstMac = 3,
    WowlanTcpSrcPort = 4,
    WowlanTcpDstPort = 5,
    WowlanTcpDataPayload = 6,
    WowlanTcpDataPayloadSeq = 7,
    WowlanTcpDataPayloadToken = 8,
    WowlanTcpDataInterval = 9,
    WowlanTcpWakePayload = 10,
    WowlanTcpWakeMask = 11,
}

impl NlAttrType for Nl80211WowlanTcpAttrs {}

/// nl80211AttrCoalesceRule
///
/// Enumeration from nl80211/nl80211.h:4174
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211AttrCoalesceRule {
    CoalesceRuleInvalid = 0,
    AttrCoalesceRuleDelay = 1,
    AttrCoalesceRuleCondition = 2,
    AttrCoalesceRulePktPattern = 3,
}

impl NlAttrType for Nl80211AttrCoalesceRule {}

/// nl80211CoalesceCondition
///
/// Enumeration from nl80211/nl80211.h:4192
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211CoalesceCondition {
    CoalesceConditionMatch = 0,
    CoalesceConditionNoMatch = 1,
}

impl NlAttrType for Nl80211CoalesceCondition {}

/// nl80211IfaceLimitAttrs
///
/// Enumeration from nl80211/nl80211.h:4207
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211IfaceLimitAttrs {
    IfaceLimitUnspec = 0,
    IfaceLimitMax = 1,
    IfaceLimitTypes = 2,
}

impl NlAttrType for Nl80211IfaceLimitAttrs {}

/// nl80211IfCombinationAttrs
///
/// Enumeration from nl80211/nl80211.h:4263
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211IfCombinationAttrs {
    IfaceCombUnspec = 0,
    IfaceCombLimits = 1,
    IfaceCombMaxnum = 2,
    IfaceCombStaApBiMatch = 3,
    IfaceCombNumChannels = 4,
    IfaceCombRadarDetectWidths = 5,
    IfaceCombRadarDetectRegions = 6,
}

impl NlAttrType for Nl80211IfCombinationAttrs {}

/// nl80211PlinkState
///
/// Enumeration from nl80211/nl80211.h:4296
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211PlinkState {
    PlinkListen = 0,
    PlinkOpnSnt = 1,
    PlinkOpnRcvd = 2,
    PlinkCnfRcvd = 3,
    PlinkEstab = 4,
    PlinkHolding = 5,
    PlinkBlocked = 6,
}

impl NlAttrType for Nl80211PlinkState {}

/// plinkActions
///
/// Enumeration from nl80211/nl80211.h:4318
#[neli_enum(serialized_type = "u16")]
pub enum PlinkActions {
    PlinkActionNoAction = 0,
    PlinkActionOpen = 1,
    PlinkActionBlock = 2,
}

impl NlAttrType for PlinkActions {}

/// nl80211RekeyData
///
/// Enumeration from nl80211/nl80211.h:4340
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211RekeyData {
    RekeyDataInvalid = 0,
    RekeyDataKek = 1,
    RekeyDataKck = 2,
    RekeyDataReplayCtr = 3,
}

impl NlAttrType for Nl80211RekeyData {}

/// nl80211HiddenSsid
///
/// Enumeration from nl80211/nl80211.h:4360
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211HiddenSsid {
    HiddenSsidNotInUse = 0,
    HiddenSsidZeroLen = 1,
    HiddenSsidZeroContents = 2,
}

impl NlAttrType for Nl80211HiddenSsid {}

/// nl80211StaWmeAttr
///
/// Enumeration from nl80211/nl80211.h:4376
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211StaWmeAttr {
    StaWmeInvalid = 0,
    StaWmeUapsdQueues = 1,
    StaWmeMaxSp = 2,
}

impl NlAttrType for Nl80211StaWmeAttr {}

/// nl80211PmksaCandidateAttr
///
/// Enumeration from nl80211/nl80211.h:4398
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211PmksaCandidateAttr {
    PmksaCandidateInvalid = 0,
    PmksaCandidateIndex = 1,
    PmksaCandidateBssid = 2,
    PmksaCandidatePreauth = 3,
}

impl NlAttrType for Nl80211PmksaCandidateAttr {}

/// nl80211TdlsOperation
///
/// Enumeration from nl80211/nl80211.h:4417
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211TdlsOperation {
    TdlsDiscoveryReq = 0,
    TdlsSetup = 1,
    TdlsTeardown = 2,
    TdlsEnableLink = 3,
    TdlsDisableLink = 4,
}

impl NlAttrType for Nl80211TdlsOperation {}

/// nl80211FeatureFlags
///
/// Enumeration from nl80211/nl80211.h:4526
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211FeatureFlags {
    FeatureSkTxStatus = 1 << 0,
    FeatureHtIbss = 1 << 1,
    FeatureInactivityTimer = 1 << 2,
    FeatureCellBaseRegHints = 1 << 3,
    FeatureP2pDeviceNeedsChannel = 1 << 4,
    FeatureSae = 1 << 5,
    FeatureLowPriorityScan = 1 << 6,
    FeatureScanFlush = 1 << 7,
    FeatureApScan = 1 << 8,
    FeatureVifTxpower = 1 << 9,
    FeatureNeedObssScan = 1 << 10,
    FeatureP2pGoCtwin = 1 << 11,
    FeatureP2pGoOppps = 1 << 12,
    FeatureAdvertiseChanLimits = 1 << 14,
    FeatureFullApClientState = 1 << 15,
    // FeatureUserspaceMpm          =1 << 16,
    // FeatureActiveMonitor         =1 << 17,
    // FeatureApModeChanWidthChange =1 << 18,
    // FeatureDsParamSetIeInProbes  =1 << 19,
    // FeatureWfaTpcIeInProbes      =1 << 20,
    // FeatureQuiet                 =1 << 21,
    // FeatureTxPowerInsertion      =1 << 22,
    // FeatureAcktoEstimation       =1 << 23,
    // FeatureStaticSmps            =1 << 24,
    // FeatureDynamicSmps           =1 << 25,
    // FeatureSupportsWmmAdmission  =1 << 26,
    // FeatureMacOnCreate           =1 << 27,
    // FeatureTdlsChannelSwitch     =1 << 28,
    // FeatureScanRandomMacAddr     =1 << 29,
    // FeatureSchedScanRandomMacAddr=1 << 30,
    // FeatureNdRandomMacAddr       =1 << 31
}

impl NlAttrType for Nl80211FeatureFlags {}

/// nl80211ExtFeatureIndex
///
/// Enumeration from nl80211/nl80211.h:4595
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211ExtFeatureIndex {
    ExtFeatureVhtIbss = 0,
    ExtFeatureRrm = 1,
    ExtFeatureMuMimoAirSniffer = 2,
    ExtFeatureScanStartTime = 3,
    ExtFeatureBssParentTsf = 4,
    ExtFeatureSetScanDwell = 5,
    ExtFeatureBeaconRateLegacy = 6,
    ExtFeatureBeaconRateHt = 7,
    ExtFeatureBeaconRateVht = 8,
}

impl NlAttrType for Nl80211ExtFeatureIndex {}

/// nl80211ProbeRespOffloadSupportAttr
///
/// Enumeration from nl80211/nl80211.h:4625
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211ProbeRespOffloadSupportAttr {
    ProbeRespOffloadSupportWps = 1 << 0,
    ProbeRespOffloadSupportWps2 = 1 << 1,
    ProbeRespOffloadSupportP2p = 1 << 2,
    ProbeRespOffloadSupport80211u = 1 << 3,
}

impl NlAttrType for Nl80211ProbeRespOffloadSupportAttr {}

/// nl80211ConnectFailedReason
///
/// Enumeration from nl80211/nl80211.h:4638
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211ConnectFailedReason {
    ConnFailMaxClients = 0,
    ConnFailBlockedClient = 1,
}

impl NlAttrType for Nl80211ConnectFailedReason {}

/// nl80211ScanFlags
///
/// Enumeration from nl80211/nl80211.h:4667
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211ScanFlags {
    ScanFlagLowPriority = 1 << 0,
    ScanFlagFlush = 1 << 1,
    ScanFlagAp = 1 << 2,
    ScanFlagRandomAddr = 1 << 3,
}

impl NlAttrType for Nl80211ScanFlags {}

/// nl80211AclPolicy
///
/// Enumeration from nl80211/nl80211.h:4687
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211AclPolicy {
    AclPolicyAcceptUnlessListed = 0,
    AclPolicyDenyUnlessListed = 1,
}

impl NlAttrType for Nl80211AclPolicy {}

/// nl80211SmpsMode
///
/// Enumeration from nl80211/nl80211.h:4702
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211SmpsMode {
    SmpsOff = 0,
    SmpsStatic = 1,
    SmpsDynamic = 2,
}

impl NlAttrType for Nl80211SmpsMode {}

/// nl80211RadarEvent
///
/// Enumeration from nl80211/nl80211.h:4726
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211RadarEvent {
    RadarDetected = 0,
    RadarCacFinished = 1,
    RadarCacAborted = 2,
    RadarNopFinished = 3,
}

impl NlAttrType for Nl80211RadarEvent {}

/// nl80211DfsState
///
/// Enumeration from nl80211/nl80211.h:4744
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211DfsState {
    DfsUsable = 0,
    DfsUnavailable = 1,
    DfsAvailable = 2,
}

impl NlAttrType for Nl80211DfsState {}

/// nl80211ProtocolFeatures
///
/// Enumeration from nl80211/nl80211.h:4758
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211ProtocolFeatures {
    ProtocolFeatureSplitWiphyDump = 1 << 0,
}

impl NlAttrType for Nl80211ProtocolFeatures {}

/// nl80211CritProtoId
///
/// Enumeration from nl80211/nl80211.h:4771
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211CritProtoId {
    CritProtoUnspec = 0,
    CritProtoDhcp = 1,
    CritProtoEapol = 2,
    CritProtoApipa = 3,
}

impl NlAttrType for Nl80211CritProtoId {}

/// nl80211RxmgmtFlags
///
/// Enumeration from nl80211/nl80211.h:4790
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211RxmgmtFlags {
    RxmgmtFlagAnswered = 1 << 0,
}

impl NlAttrType for Nl80211RxmgmtFlags {}

/// nl80211TdlsPeerCapability
///
/// Enumeration from nl80211/nl80211.h:4824
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211TdlsPeerCapability {
    TdlsPeerHt = 1 << 0,
    TdlsPeerVht = 1 << 1,
    TdlsPeerWmm = 1 << 2,
}

impl NlAttrType for Nl80211TdlsPeerCapability {}

/// nl80211SchedScanPlan
///
/// Enumeration from nl80211/nl80211.h:4843
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211SchedScanPlan {
    SchedScanPlanInvalid = 0,
    SchedScanPlanInterval = 1,
    SchedScanPlanIterations = 2,
}

impl NlAttrType for Nl80211SchedScanPlan {}

/// nl80211BssSelectAttr
///
/// Enumeration from nl80211/nl80211.h:4887
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211BssSelectAttr {
    BssSelectAttrInvalid = 0,
    BssSelectAttrRssi = 1,
    BssSelectAttrBandPref = 2,
    BssSelectAttrRssiAdjust = 3,
}

impl NlAttrType for Nl80211BssSelectAttr {}

/// nl80211NanDualBandConf
///
/// Enumeration from nl80211/nl80211.h:4907
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211NanDualBandConf {
    NanBandDefault = 1 << 0,
    NanBand2ghz = 1 << 1,
    NanBand5ghz = 1 << 2,
}

impl NlAttrType for Nl80211NanDualBandConf {}

/// nl80211NanFunctionType
///
/// Enumeration from nl80211/nl80211.h:4922
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211NanFunctionType {
    NanFuncPublish = 0,
    NanFuncSubscribe = 1,
    NanFuncFollowUp = 2,
    NanFuncTypeAfterLast = 3,
    NanFuncMaxType = 2,
}

impl NlAttrType for Nl80211NanFunctionType {}

/// nl80211NanPublishType
///
/// Enumeration from nl80211/nl80211.h:4940
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211NanPublishType {
    NanSolicitedPublish = 1 << 0,
    NanUnsolicitedPublish = 1 << 1,
}

impl NlAttrType for Nl80211NanPublishType {}

/// nl80211NanFuncTermReason
///
/// Enumeration from nl80211/nl80211.h:4954
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211NanFuncTermReason {
    NanFuncTermReasonUserRequest = 0,
    NanFuncTermReasonTtlExpired = 1,
    NanFuncTermReasonError = 2,
}

impl NlAttrType for Nl80211NanFuncTermReason {}

/// nl80211NanFuncAttributes
///
/// Enumeration from nl80211/nl80211.h:5006
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211NanFuncAttributes {
    NanFuncInvalid = 0,
    NanFuncType = 1,
    NanFuncServiceId = 2,
    NanFuncPublishType = 3,
    NanFuncPublishBcast = 4,
    NanFuncSubscribeActive = 5,
    NanFuncFollowUpId = 6,
    NanFuncFollowUpReqId = 7,
    NanFuncFollowUpDest = 8,
    NanFuncCloseRange = 9,
    NanFuncTtl = 10,
    NanFuncServiceInfo = 11,
    NanFuncSrf = 12,
    NanFuncRxMatchFilter = 13,
    NanFuncTxMatchFilter = 14,
    NanFuncInstanceId = 15,
    NanFuncTermReason = 16,
}

impl NlAttrType for Nl80211NanFuncAttributes {}

/// nl80211NanSrfAttributes
///
/// Enumeration from nl80211/nl80211.h:5045
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211NanSrfAttributes {
    NanSrfInvalid = 0,
    NanSrfInclude = 1,
    NanSrfBf = 2,
    NanSrfBfIdx = 3,
    NanSrfMacAddrs = 4,
}

impl NlAttrType for Nl80211NanSrfAttributes {}

/// nl80211NanMatchAttributes
///
/// Enumeration from nl80211/nl80211.h:5070
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211NanMatchAttributes {
    NanMatchInvalid = 0,
    NanMatchFuncLocal = 1,
    NanMatchFuncPeer = 2,
}

impl NlAttrType for Nl80211NanMatchAttributes {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operstate {
    Up,
    Down,
    Testing,
    Unknown,
    Dormant,
    NotPresent,
    LowerLayerDown,
}

impl Operstate {
    // A method to convert from a numerical value to an Operstate, if applicable
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Operstate::Unknown,
            1 => Operstate::NotPresent,
            2 => Operstate::Down,
            3 => Operstate::LowerLayerDown,
            4 => Operstate::Testing,
            5 => Operstate::Dormant,
            6 => Operstate::Up,
            _ => Operstate::Unknown, // Default or error case
        }
    }

    // Method to convert enum variants to a string representation
    pub fn to_string(&self) -> &str {
        match self {
            Operstate::Up => "Up",
            Operstate::Down => "Down",
            Operstate::Testing => "Testing",
            Operstate::Unknown => "Unknown",
            Operstate::Dormant => "Dormant",
            Operstate::NotPresent => "Not Present",
            Operstate::LowerLayerDown => "Lower Layer Down",
        }
    }
}
