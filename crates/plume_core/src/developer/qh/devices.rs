use plist::{Date, Dictionary, Value};
use serde::Deserialize;

use crate::Error;

use super::{DeveloperSession, QHResponseMeta};
use crate::developer_endpoint;

impl DeveloperSession {
    pub async fn qh_list_devices(&self, team_id: &String) -> Result<DevicesResponse, Error> {
        let endpoint = developer_endpoint!("/QH65B2/ios/listDevices.action");

        let mut body = Dictionary::new();
        body.insert("teamId".to_string(), Value::String(team_id.clone()));

        let response = self.qh_send_request(&endpoint, Some(body)).await?;
        let response_data: DevicesResponse = plist::from_value(&Value::Dictionary(response))?;

        Ok(response_data)
    }

    pub async fn qh_add_device(
        &self,
        team_id: &String,
        device_name: &String,
        device_udid: &String,
        is_tvos: bool,
    ) -> Result<DeviceResponse, Error> {
        let endpoint = developer_endpoint!("/QH65B2/ios/addDevice.action");

        let mut body = Dictionary::new();
        body.insert("teamId".to_string(), Value::String(team_id.clone()));
        body.insert("name".to_string(), Value::String(device_name.clone()));
        body.insert(
            "deviceNumber".to_string(),
            Value::String(device_udid.clone()),
        );
        if is_tvos {
            body.insert(
                "DTDK_Platform".to_string(),
                Value::String("tvos".to_string()),
            );
            body.insert(
                "subPlatform".to_string(),
                Value::String("tvOS".to_string()),
            );
        }

        let response = self.qh_send_request(&endpoint, Some(body)).await?;
        let response_data: DeviceResponse = plist::from_value(&Value::Dictionary(response))?;

        Ok(response_data)
    }

    pub async fn qh_get_device(
        &self,
        team_id: &String,
        device_udid: &String,
    ) -> Result<Option<Device>, Error> {
        let response_data = self.qh_list_devices(team_id).await?;

        let device = response_data
            .devices
            .into_iter()
            .find(|dev| dev.device_number == *device_udid);

        Ok(device)
    }

    pub async fn qh_ensure_device(
        &self,
        team_id: &String,
        device_name: &String,
        device_udid: &String,
        is_tvos: bool,
    ) -> Result<Device, Error> {
        if let Some(device) = self.qh_get_device(team_id, device_udid).await? {
            Ok(device)
        } else {
            let response = self
                .qh_add_device(team_id, device_name, device_udid, is_tvos)
                .await?;
            Ok(response.device)
        }
    }
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DevicesResponse {
    pub devices: Vec<Device>,
    #[serde(flatten)]
    pub meta: QHResponseMeta,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DeviceResponse {
    pub device: Device,
    #[serde(flatten)]
    pub meta: QHResponseMeta,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    device_id: String,
    name: String,
    device_number: String,
    device_platform: String,
    status: String,
    device_class: String,
    expiration_date: Option<Date>,
}
