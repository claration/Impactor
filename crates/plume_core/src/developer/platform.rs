use plist::{Dictionary, Value};

/// Platform an Apple developer-portal request applies to. The portal's URL path is `ios` for
/// every platform; a non-iOS target is selected with request fields instead.
///
/// Threaded through `qh_download_team_prov_profile` (`qh/profile.rs`), the device methods in
/// `qh/devices.rs`, and the App ID methods in `qh/app_ids.rs`. `qh/teams.rs`, `qh/certs.rs` and
/// `qh/app_groups.rs` are deliberately left untouched: certificates and app groups were never
/// proven to need these fields against Apple's live API, and every additional call site that
/// starts sending them is additional risk to the iOS path that every existing user depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeveloperPlatform {
    #[default]
    IOs,
    TvOs,
}

impl DeveloperPlatform {
    /// Fields identifying this platform to the portal. Empty for iOS, which is the portal's
    /// default and must keep sending byte-identical requests to what it sent before.
    pub fn request_fields(self) -> &'static [(&'static str, &'static str)] {
        match self {
            DeveloperPlatform::IOs => &[],
            DeveloperPlatform::TvOs => &[("DTDK_Platform", "tvos"), ("subPlatform", "tvOS")],
        }
    }

    /// Inserts this platform's request fields into `body`.
    ///
    /// For `IOs`, `request_fields()` is empty, so this returns without touching `body` at all -
    /// an iOS request body must stay byte-identical to what it was before tvOS support existed,
    /// and that invariant is what this early return enforces.
    pub fn apply_to(self, body: &mut Dictionary) {
        let fields = self.request_fields();
        if fields.is_empty() {
            return;
        }
        for (key, value) in fields {
            body.insert((*key).to_string(), Value::String((*value).to_string()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_ios() {
        assert_eq!(DeveloperPlatform::default(), DeveloperPlatform::IOs);
    }

    #[test]
    fn ios_request_fields_are_empty() {
        assert!(DeveloperPlatform::IOs.request_fields().is_empty());
    }

    #[test]
    fn tvos_request_fields_are_exact() {
        assert_eq!(
            DeveloperPlatform::TvOs.request_fields(),
            &[("DTDK_Platform", "tvos"), ("subPlatform", "tvOS")]
        );
    }

    #[test]
    fn ios_apply_to_leaves_dictionary_unchanged() {
        let mut body = Dictionary::new();
        body.insert("teamId".to_string(), Value::String("T123".to_string()));
        body.insert("appIdId".to_string(), Value::String("A456".to_string()));
        let original = body.clone();

        DeveloperPlatform::IOs.apply_to(&mut body);

        assert_eq!(body, original);
        assert_eq!(body.keys().count(), 2);
    }

    #[test]
    fn tvos_apply_to_adds_exactly_the_two_platform_fields() {
        let mut body = Dictionary::new();
        body.insert("teamId".to_string(), Value::String("T123".to_string()));
        body.insert("appIdId".to_string(), Value::String("A456".to_string()));

        DeveloperPlatform::TvOs.apply_to(&mut body);

        assert_eq!(body.keys().count(), 4);
        assert_eq!(body.get("teamId").and_then(Value::as_string), Some("T123"));
        assert_eq!(body.get("appIdId").and_then(Value::as_string), Some("A456"));
        assert_eq!(
            body.get("DTDK_Platform").and_then(Value::as_string),
            Some("tvos")
        );
        assert_eq!(
            body.get("subPlatform").and_then(Value::as_string),
            Some("tvOS")
        );
    }
}
