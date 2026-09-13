use plist::{Dictionary, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeveloperPlatform {
    #[default]
    Ios,
    Tvos,
}

impl DeveloperPlatform {
    pub fn from_device_metadata(
        product_type: Option<&str>,
        device_class: Option<&str>,
        network_transport: bool,
    ) -> Self {
        if network_transport
            || product_type.is_some_and(|value| value.starts_with("AppleTV"))
            || device_class.is_some_and(|value| value.eq_ignore_ascii_case("AppleTV"))
        {
            Self::Tvos
        } else {
            Self::Ios
        }
    }

    pub fn request_fields(self) -> &'static [(&'static str, &'static str)] {
        match self {
            DeveloperPlatform::Ios => &[],
            DeveloperPlatform::Tvos => &[("DTDK_Platform", "tvos"), ("subPlatform", "tvOS")],
        }
    }

    pub fn capabilities_filter(self) -> &'static str {
        match self {
            DeveloperPlatform::Ios => "IOS",
            DeveloperPlatform::Tvos => "TVOS",
        }
    }

    pub fn apply_to(self, body: &mut Dictionary) {
        let fields = self.request_fields();
        if fields.is_empty() {
            return;
        }
        for (key, value) in fields {
            body.insert((*key).to_string(), Value::String((*value).to_string()));
        }
    }

    pub fn profile_platforms(self) -> &'static [&'static str] {
        match self {
            Self::Ios => &["ios", "iphoneos"],
            Self::Tvos => &["tvos"],
        }
    }

    pub fn matches_profile_platform(self, value: &str) -> bool {
        self.profile_platforms()
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(value))
    }
}

impl std::fmt::Display for DeveloperPlatform {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeveloperPlatform::Ios => formatter.write_str("iOS"),
            DeveloperPlatform::Tvos => formatter.write_str("tvOS"),
        }
    }
}
