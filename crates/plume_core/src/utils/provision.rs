use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::developer::DeveloperPlatform;
use crate::utils::TEAM_ID_REGEX;
use crate::{Error, MachO};
use plist::{Date, Dictionary, Value};
use x509_certificate::CapturedX509Certificate;

#[derive(Clone)]
pub struct MobileProvision {
    pub data: Vec<u8>,
    entitlements: Dictionary,
    expiration_date: Date,
    platforms: Vec<String>,
    provisioned_devices: Vec<String>,
    developer_certificates: Vec<Vec<u8>>,
}

impl MobileProvision {
    pub fn load_with_path<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        Self::load_with_bytes(fs::read(path)?)
    }

    pub fn load_with_bytes(data: Vec<u8>) -> Result<Self, Error> {
        let (
            entitlements,
            expiration_date,
            platforms,
            provisioned_devices,
            developer_certificates,
        ) = Self::extract_profile_data(&data)?;

        Ok(Self {
            data,
            entitlements,
            expiration_date,
            platforms,
            provisioned_devices,
            developer_certificates,
        })
    }

    pub fn merge_entitlements(
        &mut self,
        binary_path: PathBuf,
        new_application_id: &str,
    ) -> Result<(), Error> {
        let macho = MachO::new(&binary_path)?;
        let binary_entitlements = macho
            .entitlements()
            .clone()
            .ok_or(Error::ProvisioningEntitlementsUnknown)?;

        let new_team_id = self
            .entitlements
            .get("com.apple.developer.team-identifier")
            .and_then(Value::as_string)
            .map(str::to_owned);

        crate::utils::merge_entitlements(
            &mut self.entitlements,
            &binary_entitlements,
            &new_team_id,
            &Some(new_application_id.to_string()),
        );

        Ok(())
    }

    pub fn entitlements(&self) -> &Dictionary {
        &self.entitlements
    }

    pub fn expiration_date(&self) -> &Date {
        &self.expiration_date
    }

    pub fn entitlements_as_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        Value::Dictionary(self.entitlements.clone()).to_writer_xml(&mut buf)?;
        Ok(buf)
    }

    pub fn bundle_id(&self) -> Option<String> {
        let app_id = self
            .entitlements
            .get("application-identifier")?
            .as_string()?;

        let re = regex::Regex::new(TEAM_ID_REGEX).ok()?;
        Some(re.replace(app_id, "").to_string())
    }

    pub fn validate_for(
        &self,
        platform: DeveloperPlatform,
        bundle_id: &str,
        device_udid: Option<&str>,
        certificate_der: Option<&[u8]>,
        requested_entitlements: Option<&Dictionary>,
    ) -> Result<(), Error> {
        if self.platforms.is_empty()
            || !self
                .platforms
                .iter()
                .any(|value| platform.matches_profile_platform(value))
        {
            return Err(Error::ProvisioningProfileInvalid(format!(
                "profile does not target {}",
                platform
            )));
        }

        if SystemTime::now() >= SystemTime::from(self.expiration_date) {
            return Err(Error::ProvisioningProfileInvalid(
                "profile is expired".to_string(),
            ));
        }

        let application_identifier = self
            .entitlements
            .get("application-identifier")
            .and_then(Value::as_string)
            .ok_or_else(|| {
                Error::ProvisioningProfileInvalid(
                    "profile has no application identifier".to_string(),
                )
            })?;
        if !application_identifier_grants(application_identifier, bundle_id) {
            return Err(Error::ProvisioningProfileInvalid(format!(
                "application identifier {application_identifier:?} does not match {bundle_id:?}"
            )));
        }

        if let Some(udid) = device_udid {
            if !is_valid_device_udid(udid)
                || !self
                    .provisioned_devices
                    .iter()
                    .any(|value| value.eq_ignore_ascii_case(udid))
            {
                return Err(Error::ProvisioningProfileInvalid(format!(
                    "profile does not contain selected Apple TV UDID {udid}"
                )));
            }
        }

        let Some(certificate_der) = certificate_der else {
            return Err(Error::ProvisioningProfileInvalid(
                "active signing certificate is unavailable".to_string(),
            ));
        };
        if !self
            .developer_certificates
            .iter()
            .any(|certificate| certificate.as_slice() == certificate_der)
        {
            return Err(Error::ProvisioningProfileInvalid(
                "profile does not contain the active signing certificate".to_string(),
            ));
        }
        let certificate = CapturedX509Certificate::from_der(certificate_der)?;
        if !certificate.time_constraints_valid(None) {
            return Err(Error::ProvisioningProfileInvalid(
                "active signing certificate is expired or not yet valid".to_string(),
            ));
        }

        if let Some(requested_entitlements) = requested_entitlements {
            for (key, requested) in requested_entitlements {
                if matches!(
                    key.as_str(),
                    "application-identifier" | "com.apple.developer.team-identifier"
                ) {
                    continue;
                }

                let Some(granted) = self.entitlements.get(key) else {
                    return Err(Error::ProvisioningProfileInvalid(format!(
                        "profile does not grant entitlement {key:?}"
                    )));
                };
                if !value_grants(granted, requested) {
                    return Err(Error::ProvisioningProfileInvalid(format!(
                        "profile does not grant entitlement {key:?}"
                    )));
                }
            }
        }

        Ok(())
    }

    pub fn validate_final_entitlements(
        &self,
        platform: DeveloperPlatform,
        bundle_id: &str,
        device_udid: Option<&str>,
        certificate_der: Option<&[u8]>,
        entitlements: &Dictionary,
    ) -> Result<(), Error> {
        self.validate_for(
            platform,
            bundle_id,
            device_udid,
            certificate_der,
            None,
        )?;

        let profile_application_identifier = self
            .entitlements
            .get("application-identifier")
            .and_then(Value::as_string)
            .ok_or_else(|| {
                Error::ProvisioningProfileInvalid(
                    "profile has no application identifier".to_string(),
                )
            })?;
        let application_identifier = entitlements
            .get("application-identifier")
            .and_then(Value::as_string)
            .ok_or_else(|| {
                Error::ProvisioningProfileInvalid(
                    "signed executable has no application identifier".to_string(),
                )
            })?;
        let final_bundle_id = application_identifier_bundle_id(application_identifier)
            .ok_or_else(|| {
                Error::ProvisioningProfileInvalid(
                    "signed executable has an invalid application identifier".to_string(),
                )
            })?;
        if final_bundle_id != bundle_id
            || !application_identifier_grants(profile_application_identifier, final_bundle_id)
        {
            return Err(Error::ProvisioningProfileInvalid(format!(
                "signed executable application identifier {application_identifier:?} does not match {bundle_id:?}"
            )));
        }

        let profile_team_identifier = self
            .entitlements
            .get("com.apple.developer.team-identifier")
            .and_then(Value::as_string)
            .or_else(|| application_identifier_team(profile_application_identifier))
            .ok_or_else(|| {
                Error::ProvisioningProfileInvalid(
                    "profile has no team identifier".to_string(),
                )
            })?;
        let final_team_identifier = entitlements
            .get("com.apple.developer.team-identifier")
            .and_then(Value::as_string)
            .or_else(|| application_identifier_team(application_identifier))
            .ok_or_else(|| {
                Error::ProvisioningProfileInvalid(
                    "signed executable has no team identifier".to_string(),
                )
            })?;
        if final_team_identifier != profile_team_identifier
            || application_identifier_team(profile_application_identifier)
                .is_some_and(|team| team != profile_team_identifier)
            || application_identifier_team(application_identifier)
                .is_some_and(|team| team != profile_team_identifier)
        {
            return Err(Error::ProvisioningProfileInvalid(
                "signed executable team identifier does not match the provisioning profile"
                    .to_string(),
            ));
        }

        for (key, requested) in entitlements {
            if key == "application-identifier" || key == "com.apple.developer.team-identifier" {
                continue;
            }

            let Some(granted) = self.entitlements.get(key) else {
                return Err(Error::ProvisioningProfileInvalid(format!(
                    "profile does not grant entitlement {key:?}"
                )));
            };
            if !value_grants(granted, requested) {
                return Err(Error::ProvisioningProfileInvalid(format!(
                    "profile does not grant entitlement {key:?}"
                )));
            }
        }

        Ok(())
    }

    fn extract_profile_data(
        data: &[u8],
    ) -> Result<(Dictionary, Date, Vec<String>, Vec<String>, Vec<Vec<u8>>), Error> {
        let start = data
            .windows(6)
            .position(|window| window == b"<plist")
            .ok_or(Error::ProvisioningEntitlementsUnknown)?;
        let end = data
            .windows(8)
            .rposition(|window| window == b"</plist>")
            .ok_or(Error::ProvisioningEntitlementsUnknown)?
            + 8;
        let plist = Value::from_reader_xml(&data[start..end])?;
        let dictionary = plist
            .as_dictionary()
            .ok_or(Error::ProvisioningEntitlementsUnknown)?;

        let entitlements = dictionary
            .get("Entitlements")
            .and_then(Value::as_dictionary)
            .cloned()
            .ok_or(Error::ProvisioningEntitlementsUnknown)?;
        let expiration_date = dictionary
            .get("ExpirationDate")
            .and_then(Value::as_date)
            .ok_or(Error::ProvisioningEntitlementsUnknown)?;
        let platforms = string_values(dictionary.get("Platform"));
        let provisioned_devices = string_values(dictionary.get("ProvisionedDevices"));
        let developer_certificates = dictionary
            .get("DeveloperCertificates")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_data)
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default();

        Ok((
            entitlements,
            expiration_date,
            platforms,
            provisioned_devices,
            developer_certificates,
        ))
    }
}

fn string_values(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::String(value)) => vec![value.clone()],
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_string)
            .map(ToOwned::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

fn application_identifier_grants(granted: &str, requested: &str) -> bool {
    let granted_bundle_id = application_identifier_bundle_id(granted).unwrap_or(granted);

    if granted_bundle_id == requested {
        return true;
    }

    if granted_bundle_id == "*" {
        return true;
    }

    granted_bundle_id
        .strip_suffix(".*")
        .is_some_and(|prefix| {
            requested
                .strip_prefix(prefix)
                .is_some_and(|remainder| remainder.starts_with('.'))
        })
}

fn application_identifier_bundle_id(value: &str) -> Option<&str> {
    let (team, bundle_id) = value.split_once('.')?;
    if team.len() == 10
        && team
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        && !bundle_id.is_empty()
    {
        Some(bundle_id)
    } else {
        None
    }
}

fn application_identifier_team(value: &str) -> Option<&str> {
    let (team, _) = value.split_once('.')?;
    if team.len() == 10
        && team
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        Some(team)
    } else {
        None
    }
}

fn value_grants(granted: &Value, requested: &Value) -> bool {
    match (granted, requested) {
        (Value::String(granted), Value::String(requested)) => wildcard_matches(granted, requested),
        (Value::Array(granted), Value::Array(requested)) => requested
            .iter()
            .all(|requested| granted.iter().any(|granted| value_grants(granted, requested))),
        (Value::Dictionary(granted), Value::Dictionary(requested)) => requested.iter().all(
            |(key, requested)| {
                granted
                    .get(key)
                    .is_some_and(|granted| value_grants(granted, requested))
            },
        ),
        _ => granted == requested,
    }
}

fn wildcard_matches(granted: &str, requested: &str) -> bool {
    if !granted.contains('*') {
        return granted == requested;
    }

    let mut remainder = requested;
    let mut parts = granted.split('*');
    let Some(first) = parts.next() else {
        return false;
    };
    if !remainder.starts_with(first) {
        return false;
    }
    remainder = &remainder[first.len()..];

    let suffixes = parts.collect::<Vec<_>>();
    for (index, part) in suffixes.iter().enumerate() {
        if index == suffixes.len() - 1 {
            return remainder.ends_with(part);
        }
        let Some(position) = remainder.find(part) else {
            return false;
        };
        remainder = &remainder[position + part.len()..];
    }

    true
}

pub fn is_valid_device_udid(value: &str) -> bool {
    let bytes = value.as_bytes();
    let is_hex = |part: &[u8]| part.iter().all(|byte| byte.is_ascii_hexdigit());

    (bytes.len() == 40 && is_hex(bytes))
        || (bytes.len() == 25
            && bytes[8] == b'-'
            && is_hex(&bytes[..8])
            && is_hex(&bytes[9..]))
}
