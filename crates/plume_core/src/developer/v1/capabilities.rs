use plist::Dictionary;
use serde::Deserialize;
use serde_json::json;

use super::{DeveloperSession, RequestType};
use crate::developer_endpoint;

use crate::Error;
use std::collections::HashSet;

const FREE_DEVELOPER_ACCOUNT_UNALLOWED_CAPABILITIES: &[&str] = &[
    "AUTOFILL_CREDENTIAL_PROVIDER",
    "APPLE_ID_AUTH",
    "NETWORK_SLICING",
    "MERCHANT_ACCESSIBILITY_CONTROL",
    "ICLOUD",
    "ICLOUD_EXTENDED_SHARE_ACCESS",
    "IN_APP_PURCHASE",
    "JOURNALING_SUGGESTIONS",
    "MDM_MANAGED_ASSOCIATED_DOMAINS",
];

impl DeveloperSession {
    pub async fn v1_list_capabilities(&self, team: &String) -> Result<CapabilitiesResponse, Error> {
        let endpoint = developer_endpoint!("/v1/capabilities");

        let platform_filter = if self.platform == "tvos" { "TV_OS" } else { "IOS" };
        let body = json!({
            "teamId": team,
            "urlEncodedQueryParams": format!("filter[platform]={}", platform_filter)
        });

        let response = self
            .v1_send_request(&endpoint, Some(body), Some(RequestType::Get))
            .await?;
        let response_data: CapabilitiesResponse = serde_json::from_value(response)?;

        Ok(response_data)
    }

    pub async fn v1_request_capabilities_for_entitlements(
        &self,
        team: &String,
        id: &String,
        entitlements: &Dictionary,
    ) -> Result<(), Error> {
        let capabilities = self.v1_list_capabilities(team).await?.data;
        let entitlement_keys: HashSet<&str> = entitlements.keys().map(|k| k.as_str()).collect();

        // Collect capability IDs that match entitlement keys and are allowed for free accounts
        let capabilities_to_enable: Vec<String> = capabilities
            .iter()
            .filter(|cap| !FREE_DEVELOPER_ACCOUNT_UNALLOWED_CAPABILITIES.contains(&cap.id.as_str()))
            .filter_map(|cap| {
                cap.attributes
                    .entitlements
                    .as_ref()?
                    .iter()
                    .find(|e| entitlement_keys.contains(e.profile_key.as_str()))
                    .map(|_| cap.id.clone())
            })
            .collect();

        self.v1_update_app_id(team, id, capabilities_to_enable.clone())
            .await?;

        Ok(())
    }
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CapabilitiesResponse {
    pub data: Vec<Capability>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Capability {
    pub id: String,
    pub attributes: CapabilityAttributes,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityAttributes {
    pub entitlements: Option<Vec<CapabilityEntitlement>>,
    pub supports_wildcard: bool,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityEntitlement {
    pub profile_key: String,
}
