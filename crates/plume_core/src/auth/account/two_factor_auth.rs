use std::str::FromStr;

use crate::Error;
use base64::{Engine, engine::general_purpose};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use crate::auth::{Account, AuthenticationExtras, LoginState, PhoneNumber, VerifyBody, VerifyCode};

impl Account {
    pub async fn send_2fa_to_devices(&self) -> Result<LoginState, Error> {
        let headers = self.build_2fa_headers(false).await;

        let res = self
            .client
            .get("https://gsa.apple.com/auth/verify/trusteddevice")
            .headers(headers)
            .send()
            .await?;

        let status_code = res.status();

        if !status_code.is_success() {
            return Err(Error::AuthSrpWithMessage(
                status_code.as_u16() as i64,
                "Failed to send 2FA to devices".to_string(),
            ));
        }

        return Ok(LoginState::Needs2FAVerification);
    }

    pub async fn send_sms_2fa_to_devices(&self, phone_id: u32) -> Result<LoginState, Error> {
        let headers = self.build_2fa_headers(true).await;

        let body = VerifyBody {
            phone_number: PhoneNumber { id: phone_id },
            mode: "sms".to_string(),
            security_code: None,
        };

        let res = self
            .client
            .put("https://gsa.apple.com/auth/verify/phone")
            .headers(headers)
            .json(&body)
            .send()
            .await?;

        let status_code = res.status();

        if !status_code.is_success() {
            return Err(Error::AuthSrpWithMessage(
                status_code.as_u16() as i64,
                "Failed to send SMS 2FA to devices".to_string(),
            ));
        }

        return Ok(LoginState::NeedsSMS2FAVerification(body));
    }

    pub async fn get_auth_extras(&self) -> Result<AuthenticationExtras, Error> {
        let headers = self.build_2fa_headers(true);

        let req = self
            .client
            .get("https://gsa.apple.com/auth")
            .headers(headers.await)
            .header("Accept", "application/json")
            .send()
            .await?;
        let status = req.status().as_u16();
        let mut new_state = req.json::<AuthenticationExtras>().await?;
        if status == 201 {
            new_state.new_state = Some(LoginState::NeedsSMS2FAVerification(VerifyBody {
                phone_number: PhoneNumber {
                    id: new_state.trusted_phone_numbers.first().unwrap().id,
                },
                mode: "sms".to_string(),
                security_code: None,
            }));
        }

        Ok(new_state)
    }

    pub async fn verify_2fa(&self, code: String) -> Result<LoginState, Error> {
        let headers = self.build_2fa_headers(false);
        let res = self
            .client
            .get("https://gsa.apple.com/grandslam/GsService2/validate")
            .headers(headers.await)
            .header(
                HeaderName::from_str("security-code").unwrap(),
                HeaderValue::from_str(&code).unwrap(),
            )
            .send()
            .await?;

        let status = res.status();
        let body = res.text().await?;
        if !status.is_success() {
            // Same rationale as `parse_response`: surface the HTTP status and
            // the request stage instead of a confusing plist/HTML parse error.
            return Err(Error::AuthSrpWithMessage(
                status.as_u16() as i64,
                format!(
                    "Apple authentication request to https://gsa.apple.com/grandslam/GsService2/validate returned HTTP {status} (expected a GSA plist)."
                ),
            ));
        }
        let res: plist::Dictionary = plist::from_bytes(body.as_bytes())?;

        super::check_error(&res)?;

        Ok(LoginState::NeedsLogin)
    }

    pub async fn verify_sms_2fa(
        &self,
        code: String,
        mut body: VerifyBody,
    ) -> Result<LoginState, Error> {
        let headers = self.build_2fa_headers(true).await;
        body.security_code = Some(VerifyCode { code });
        let res = self
            .client
            .post("https://gsa.apple.com/auth/verify/phone/securitycode")
            .headers(headers)
            .json(&body)
            .send()
            .await?;

        let status_code = res.status();

        // TODO: 423 http code may occur, in this case we to ask for sending
        // last code sent (unlikely it would even work), or try again later
        if !status_code.is_success() {
            return Err(Error::Bad2faCode);
        }

        Ok(LoginState::NeedsLogin)
    }

    async fn build_2fa_headers(&self, sms: bool) -> HeaderMap {
        let spd = self.spd.as_ref().unwrap();
        let dsid = spd.get("adsid").unwrap().as_string().unwrap();
        let token = spd.get("GsIdmsToken").unwrap().as_string().unwrap();

        let identity_token = general_purpose::STANDARD.encode(format!("{}:{}", dsid, token));

        let mut headers = HeaderMap::new();
        let valid_anisette = self.get_anisette().await;
        for (k, v) in valid_anisette.generate_headers(false, true, true) {
            headers.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(&v).unwrap(),
            );
        }
        if !sms {
            headers.insert("Content-Type", HeaderValue::from_static("text/x-xml-plist"));
            headers.insert("Accept", HeaderValue::from_static("text/x-xml-plist"));
        } else {
            headers.insert("Content-Type", HeaderValue::from_static("application/json"));
            headers.insert("Accept", HeaderValue::from_static("application/json"));
        }
        headers.insert("User-Agent", HeaderValue::from_static("Xcode"));
        headers.insert("Accept-Language", HeaderValue::from_static("en-us"));
        headers.append(
            "X-Apple-Identity-Token",
            HeaderValue::from_str(&identity_token).unwrap(),
        );

        if let Ok(locale) = valid_anisette.get_header("x-apple-locale") {
            headers.insert("Loc", HeaderValue::from_str(&locale).unwrap());
        }

        headers
    }
}
