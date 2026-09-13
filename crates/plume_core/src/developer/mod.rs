mod platform;
pub mod qh;
mod session;
pub mod v1;

pub use platform::DeveloperPlatform;
pub use session::{DeveloperSession, RequestType};

#[macro_export]
macro_rules! developer_endpoint {
    ($endpoint:expr) => {
        format!("https://developerservices2.apple.com/services{}", $endpoint)
    };
}

// Apple apis restrict certain characters in app names
pub fn strip_invalid_chars(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphabetic()).collect()
}
