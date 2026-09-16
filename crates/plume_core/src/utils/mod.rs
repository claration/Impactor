use plist::Value;

mod certificate;
#[cfg(feature = "tweaks")]
mod macho;
mod provision;

pub use certificate::CertificateIdentity;
#[cfg(feature = "tweaks")]
pub use macho::{MachO, MachOExt};
pub use provision::{MobileProvision, is_valid_device_udid};

pub const TEAM_ID_REGEX: &str = r"^[A-Z0-9]{10}\.";

pub fn merge_entitlements(
    base: &mut plist::Dictionary,
    additions: &plist::Dictionary,
    new_team_id: &Option<String>,
    new_application_id: &Option<String>,
) {
    // replaces wildcards in base entitlements with new application id
    // aggressive approach though, lets just hope this works :)
    if let Some(new_app_id) = new_application_id {
        fn replace_wildcard(value: &mut Value, new_app_id: &str) {
            match value {
                Value::String(s) => {
                    if s.contains('*') {
                        *s = s.replace('*', new_app_id);
                    }
                }
                Value::Array(arr) => {
                    for item in arr.iter_mut() {
                        replace_wildcard(item, new_app_id);
                    }
                }
                Value::Dictionary(dict) => {
                    for v in dict.values_mut() {
                        replace_wildcard(v, new_app_id);
                    }
                }
                _ => {}
            }
        }
        for value in base.values_mut() {
            replace_wildcard(value, new_app_id);
        }
    }

    if let Some(Value::Array(groups)) = additions.get("keychain-access-groups") {
        base.insert(
            "keychain-access-groups".to_string(),
            Value::Array(groups.clone()),
        );
    }

    // remove anything that does not match XXXXXXXXXX. (for example, com.apple.token)
    // only XXXXXXXXXX.* is allowed on keychain-access-groups
    if let Some(Value::Array(groups)) = base.get_mut("keychain-access-groups") {
        let re = regex::Regex::new(TEAM_ID_REGEX).unwrap();
        groups.retain(|g| matches!(g, Value::String(s) if re.is_match(s)));
    }

    if let Some(new_id) = new_team_id {
        if let Some(Value::Array(groups)) = base.get_mut("keychain-access-groups") {
            for group in groups.iter_mut() {
                if let Value::String(s) = group {
                    let re = regex::Regex::new(TEAM_ID_REGEX).unwrap();
                    if re.is_match(s) {
                        *s = format!("{}.{}", new_id, &s[11..]);
                    }
                }
            }
        }
    }
}
