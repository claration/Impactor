mod login;
mod token;
mod two_factor_auth;

use aes::cipher::BlockModeDecrypt;
use cbc::cipher::{KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, KeyInit, Mac};
use reqwest::Response;
use sha2::Sha256;
use srp::ClientVerifier;

use crate::Error;

pub async fn parse_response(
    res: Result<Response, reqwest::Error>,
) -> Result<plist::Dictionary, Error> {
    let res = res?;
    let status = res.status();
    let url = res.url().to_string();
    let body = res.text().await?;
    if !status.is_success() {
        // Apple's edge answers non-2xx failures (e.g. HTTP 503 when the
        // `X-MMe-Client-Info` client identifier is blocked) with a short HTML
        // page instead of a GSA plist. Report the stage (URL), the HTTP status
        // and a body snippet instead of a confusing plist/HTML parse error.
        log::debug!("GSA request to {url} failed: HTTP {status}, body: {body:?}");
        return Err(Error::AuthSrpWithMessage(
            status.as_u16() as i64,
            format!(
                "Apple authentication request to {url} returned HTTP {status} (expected a GSA plist). Body: {}",
                body_snippet(&body),
            ),
        ));
    }
    let res: plist::Dictionary = plist::from_bytes(body.as_bytes())?;
    let res: plist::Value = res.get("Response").unwrap().to_owned();
    match res {
        plist::Value::Dictionary(dict) => Ok(dict),
        _ => Err(crate::Error::Parse),
    }
}

/// Collapse a response body to a single-line snippet for error messages.
fn body_snippet(body: &str) -> String {
    const LIMIT: usize = 200;
    let single_line = body.split_whitespace().collect::<Vec<_>>().join(" ");
    if single_line.chars().count() > LIMIT {
        single_line.chars().take(LIMIT).collect::<String>() + "..."
    } else {
        single_line
    }
}

pub fn check_error(res: &plist::Dictionary) -> Result<(), Error> {
    let res = match res.get("Status") {
        Some(plist::Value::Dictionary(d)) => d,
        _ => &res,
    };

    if res.get("ec").unwrap().as_signed_integer().unwrap() != 0 {
        return Err(Error::AuthSrpWithMessage(
            res.get("ec").unwrap().as_signed_integer().unwrap().into(),
            res.get("em").unwrap().as_string().unwrap().to_owned(),
        ));
    }

    Ok(())
}

pub fn decrypt_cbc(usr: &ClientVerifier<Sha256>, data: &[u8]) -> Vec<u8> {
    let extra_data_key = create_session_key(usr, "extra data key:");
    let extra_data_iv = create_session_key(usr, "extra data iv:");
    let extra_data_iv = &extra_data_iv[..16];

    cbc::Decryptor::<aes::Aes256>::new_from_slices(&extra_data_key, extra_data_iv)
        .unwrap()
        .decrypt_padded_vec::<Pkcs7>(&data)
        .unwrap()
}

pub fn create_session_key(usr: &ClientVerifier<Sha256>, name: &str) -> Vec<u8> {
    Hmac::<Sha256>::new_from_slice(&usr.key())
        .unwrap()
        .chain_update(name.as_bytes())
        .finalize()
        .into_bytes()
        .to_vec()
}
