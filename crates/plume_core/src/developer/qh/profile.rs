use plist::{Data, Date, Dictionary, Value};
use serde::Deserialize;

use crate::Error;

use super::{DeveloperSession, QHResponseMeta};
use crate::developer::DeveloperPlatform;
use crate::developer_endpoint;

impl DeveloperSession {
    pub async fn qh_get_profile(
        &self,
        team_id: &String,
        app_id_id: &String,
        platform: DeveloperPlatform,
    ) -> Result<ProfilesResponse, Error> {
        let endpoint = developer_endpoint!("/QH65B2/ios/downloadTeamProvisioningProfile.action");

        let mut body = Dictionary::new();
        body.insert("teamId".to_string(), Value::String(team_id.clone()));
        body.insert("appIdId".to_string(), Value::String(app_id_id.clone()));
        platform.apply_to(&mut body);

        let response = self.qh_send_request(&endpoint, Some(body)).await?;
        let response_data: ProfilesResponse = plist::from_value(&Value::Dictionary(response))?;

        Ok(response_data)
    }
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ProfilesResponse {
    pub provisioning_profile: Profile,
    #[serde(flatten)]
    pub meta: QHResponseMeta,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    provisioning_profile_id: String,
    name: String,
    status: String,
    #[serde(rename = "type")]
    _type: String,
    distribution_method: String,
    pro_pro_platorm: Option<String>,
    #[serde(rename = "UUID")]
    uuid: String,
    pub date_expire: Date,
    managing_app: Option<String>,
    // app_id: AppID,
    app_id_id: String,
    pub encoded_profile: Data,
    pub filename: String,
    is_template_profile: bool,
    is_team_profile: bool,
    is_free_provisioning_profile: Option<bool>,
}
