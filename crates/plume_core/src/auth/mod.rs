pub mod account;
pub mod anisette_data;

use omnisette::AnisetteConfiguration;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::auth::anisette_data::AnisetteData;
use crate::{Error, client};

const GSA_ENDPOINT: &str = "https://gsa.apple.com/grandslam/GsService2";

#[derive(Debug, Clone)]
pub struct Account {
    pub anisette: Arc<Mutex<AnisetteData>>,
    pub spd: Option<plist::Dictionary>,
    pub client: Client,
}

impl Account {
    pub async fn new(config: AnisetteConfiguration) -> Result<Self, Error> {
        let anisette = AnisetteData::new(config).await?;
        Self::new_with_anisette(anisette)
    }

    pub fn new_with_anisette(anisette: AnisetteData) -> Result<Self, Error> {
        let client = client()?;
        Ok(Account {
            anisette: Arc::new(Mutex::new(anisette)),
            spd: None,
            client,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitRequestBody {
    #[serde(rename = "A2k")]
    a_pub: plist::Value,
    cpd: plist::Dictionary,
    #[serde(rename = "o")]
    operation: String,
    ps: Vec<String>,
    #[serde(rename = "u")]
    username: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RequestHeader {
    #[serde(rename = "Version")]
    version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitRequest {
    #[serde(rename = "Header")]
    header: RequestHeader,
    #[serde(rename = "Request")]
    request: InitRequestBody,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeRequestBody {
    #[serde(rename = "M1")]
    m: plist::Value,
    cpd: plist::Dictionary,
    c: String,
    #[serde(rename = "o")]
    operation: String,
    #[serde(rename = "u")]
    username: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeRequest {
    #[serde(rename = "Header")]
    header: RequestHeader,
    #[serde(rename = "Request")]
    request: ChallengeRequestBody,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthTokenRequestBody {
    app: Vec<String>,
    c: plist::Value,
    cpd: plist::Dictionary,
    #[serde(rename = "o")]
    operation: String,
    t: String,
    u: String,
    checksum: plist::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthTokenRequest {
    #[serde(rename = "Header")]
    header: RequestHeader,
    #[serde(rename = "Request")]
    request: AuthTokenRequestBody,
}

#[derive(Clone, Debug)]
pub struct AppToken {
    pub app_tokens: plist::Dictionary,
    pub auth_token: String,
    pub app: String,
}

#[repr(C)]
#[derive(Debug)]
pub enum LoginState {
    LoggedIn,
    NeedsDevice2FA,
    Needs2FAVerification,
    NeedsSMS2FA,
    NeedsSMS2FAVerification(VerifyBody),
    NeedsExtraStep(String),
    NeedsLogin,
}

#[derive(Serialize, Debug, Clone)]
struct VerifyCode {
    code: String,
}

#[derive(Serialize, Debug, Clone)]
struct PhoneNumber {
    id: u32,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VerifyBody {
    phone_number: PhoneNumber,
    mode: String,
    security_code: Option<VerifyCode>,
}

#[repr(C)]
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TrustedPhoneNumber {
    pub number_with_dial_code: String,
    pub last_two_digits: String,
    pub push_mode: String,
    pub id: u32,
}

/// Channel through which Apple delivered (or will deliver) the 2FA code
#[derive(Debug, Clone, PartialEq)]
pub enum TwoFactorMethod {
    /// Code pushed to the account's trusted devices
    Device,
    /// Code sent over SMS to a trusted phone number
    Sms,
}

/// Context passed to the 2FA callback so the caller can render the right prompt
/// and decide whether to fall back to SMS
#[derive(Debug, Clone)]
pub struct TwoFactorRequest {
    pub method: TwoFactorMethod,
    pub trusted_phone_numbers: Vec<TrustedPhoneNumber>,
}

/// How the caller chose to respond to a 2FA prompt
#[derive(Debug, Clone)]
pub enum TwoFactorAction {
    /// Submit the verification code the user entered
    SubmitCode(String),
    /// Request a fresh code be sent via SMS to the trusted phone number with this id
    SendSms(u32),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationExtras {
    pub trusted_phone_numbers: Vec<TrustedPhoneNumber>,
    pub recovery_url: Option<String>,
    pub cant_use_phone_number_url: Option<String>,
    pub dont_have_access_url: Option<String>,
    pub recovery_web_url: Option<String>,
    pub repair_phone_number_url: Option<String>,
    pub repair_phone_number_web_url: Option<String>,
    #[serde(skip)]
    pub new_state: Option<LoginState>,
}
