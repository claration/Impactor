use std::collections::HashMap;
use std::time::SystemTime;

use omnisette::{AUTHKIT_CLIENT_INFO, AnisetteConfiguration, AnisetteHeaders};

use crate::Error;

#[derive(Debug, Clone)]
pub struct AnisetteData {
    pub base_headers: HashMap<String, String>,
    pub generated_at: SystemTime,
    pub config: AnisetteConfiguration,
}

impl AnisetteData {
    pub async fn new(config: AnisetteConfiguration) -> Result<Self, Error> {
        let mut b = AnisetteHeaders::get_anisette_headers_provider(config.clone())?;
        let base_headers = b.provider.get_authentication_headers().await?;

        Ok(AnisetteData {
            base_headers,
            generated_at: SystemTime::now(),
            config,
        })
    }

    pub fn needs_refresh(&self) -> bool {
        let elapsed = self.generated_at.elapsed().unwrap();
        elapsed.as_secs() > 60
    }

    pub fn is_valid(&self) -> bool {
        let elapsed = self.generated_at.elapsed().unwrap();
        elapsed.as_secs() < 90
    }

    pub async fn refresh(&self) -> Result<Self, crate::Error> {
        Self::new(self.config.clone()).await
    }

    pub fn generate_headers(
        &self,
        cpd: bool,
        client_info: bool,
        app_info: bool,
    ) -> HashMap<String, String> {
        if !self.is_valid() {
            panic!("Invalid data!")
        }

        let mut headers = self.base_headers.clone();
        let old_client_info = headers.remove("X-Mme-Client-Info");

        if client_info {
            let client_info = match old_client_info {
                Some(v) => {
                    let temp = v.as_str();

                    // Report the client as `akd` instead of the hardcoded
                    // `com.apple.dt.Xcode/3594.4.19`: since early September 2026
                    // Apple's authentication edge answers HTTP 503 to any
                    // GrandSlam request carrying the Xcode client token, before
                    // any credential is checked (same approach as AltStore PR
                    // #1790). Only the client token inside `X-MMe-Client-Info`
                    // is changed here — the `com.apple.gs.xcode.auth` app
                    // identifier and `X-Xcode-Version` below are different
                    // concepts and intentionally left untouched.
                    temp.replace(
                        temp.split('<').nth(3).unwrap().split('>').nth(0).unwrap(),
                        AUTHKIT_CLIENT_INFO,
                    )
                }
                None => {
                    return headers;
                }
            };
            headers.insert("X-Mme-Client-Info".to_owned(), client_info.to_owned());
        }

        if app_info {
            headers.insert(
                "X-Apple-App-Info".to_owned(),
                "com.apple.gs.xcode.auth".to_owned(),
            );
            headers.insert("X-Xcode-Version".to_owned(), "11.2 (11B41)".to_owned());
        }

        if cpd {
            headers.insert("bootstrap".to_owned(), "true".to_owned());
            headers.insert("icscrec".to_owned(), "true".to_owned());
            headers.insert("loc".to_owned(), "en_GB".to_owned());
            headers.insert("pbe".to_owned(), "false".to_owned());
            headers.insert("prkgen".to_owned(), "true".to_owned());
            headers.insert("svct".to_owned(), "iCloud".to_owned());
        }

        headers
    }

    pub fn to_plist(&self, cpd: bool, client_info: bool, app_info: bool) -> plist::Dictionary {
        let mut plist = plist::Dictionary::new();
        for (key, value) in self.generate_headers(cpd, client_info, app_info).iter() {
            plist.insert(key.to_owned(), plist::Value::String(value.to_owned()));
        }

        plist
    }

    pub fn get_header(&self, header: &str) -> Result<String, Error> {
        let headers = self
            .generate_headers(true, true, true)
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.to_lowercase()))
            .collect::<HashMap<String, String>>();

        match headers.get(&header.to_lowercase()) {
            Some(v) => Ok(v.to_string()),
            None => Err(Error::DeveloperSessionRequestFailed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_data(client_info: &str) -> AnisetteData {
        let mut base_headers = HashMap::new();
        base_headers.insert("X-Mme-Client-Info".to_string(), client_info.to_string());
        AnisetteData {
            base_headers,
            generated_at: SystemTime::now(),
            config: AnisetteConfiguration::new(),
        }
    }

    #[test]
    fn generated_client_info_avoids_blocked_xcode_token() {
        // Bases as served by local ADI provisioning and by remote anisette
        // servers: machine/OS portions differ, the blocked Xcode token is the
        // same. Apple's edge answers HTTP 503 to all of them.
        for base in [
            "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>",
            "<Mac14,2> <macOS;15.7.5;24G624> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>",
        ] {
            let headers = test_data(base).generate_headers(false, true, false);
            let info = headers
                .get("X-Mme-Client-Info")
                .expect("X-Mme-Client-Info must be present");
            assert!(
                info.contains("com.apple.akd/1.0"),
                "expected accepted akd token, got: {info}"
            );
            assert!(
                !info.contains("com.apple.dt.Xcode"),
                "blocked Xcode token still present: {info}"
            );
            // The machine/OS portion must be preserved, not clobbered.
            let machine_os = &base[..base.find(" <com.apple").unwrap()];
            assert!(
                info.starts_with(machine_os),
                "machine/OS portion lost, got: {info}"
            );
        }
    }

    #[test]
    fn xcode_app_identifiers_are_left_untouched() {
        // `com.apple.gs.xcode.auth` (X-Apple-App-Info / apptoken app id) and
        // `X-Xcode-Version` are different concepts from the `X-MMe-Client-Info`
        // client identifier and must NOT be rewritten.
        let headers = test_data(
            "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>",
        )
        .generate_headers(false, true, true);
        assert_eq!(
            headers.get("X-Apple-App-Info").map(String::as_str),
            Some("com.apple.gs.xcode.auth")
        );
        assert_eq!(
            headers.get("X-Xcode-Version").map(String::as_str),
            Some("11.2 (11B41)")
        );
    }

    #[test]
    fn vendored_anisette_dep_ships_accepted_client_info() {
        // The vendored `omnisette` dependency is the other producer of
        // `X-MMe-Client-Info` (local ADI provisioning + remote-anisette
        // sanitization). Guard its shipped values here too, since its own
        // test harness currently does not compile standalone in this repo
        // (pre-existing missing tokio/chrono test features, unrelated to
        // this fix).
        assert!(
            !omnisette::adi_proxy::CLIENT_INFO_HEADER.contains("com.apple.dt.Xcode"),
            "blocked Xcode token in omnisette CLIENT_INFO_HEADER"
        );
        assert!(
            omnisette::adi_proxy::CLIENT_INFO_HEADER.contains(omnisette::AUTHKIT_CLIENT_INFO),
            "unexpected omnisette CLIENT_INFO_HEADER: {}",
            omnisette::adi_proxy::CLIENT_INFO_HEADER
        );
        for version in ["3594.4.19", "9999.9.99"] {
            let stale = format!(
                "<Mac14,2> <macOS;15.7.5;24G624> <com.apple.AuthKit/1 (com.apple.dt.Xcode/{version})>"
            );
            let clean = omnisette::sanitize_gsa_client_info(&stale);
            assert!(
                clean.contains("com.apple.akd/1.0") && !clean.contains("com.apple.dt.Xcode"),
                "sanitize failed for {version}: {clean}"
            );
            // Sanitized server values must also flow cleanly through
            // `generate_headers`, which preserves machine/OS portions.
            let info =
                test_data(&clean).generate_headers(false, true, false)["X-Mme-Client-Info"].clone();
            assert!(
                !info.contains("com.apple.dt.Xcode"),
                "blocked token reached final headers: {info}"
            );
        }
    }
}
