use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use chrono::Utc;
use plume_core::{
    AnisetteConfiguration, CertificateIdentity, MobileProvision, developer::DeveloperSession,
};
use plume_store::{AccountStore, RefreshDevice};
use plume_utils::{Bundle, Device, Signer, SignerMode, SignerOptions};

use crate::defaults::get_data_path;

pub type ConnectedDevices = Arc<Mutex<HashMap<String, Device>>>;

struct RefreshGuard {
    udid: String,
    tasks: Arc<Mutex<HashSet<String>>>,
}

impl Drop for RefreshGuard {
    fn drop(&mut self) {
        if let Ok(mut tasks) = self.tasks.lock() {
            tasks.remove(&self.udid);
            log::debug!("Released lock for device {}", self.udid);
        }
    }
}

pub struct RefreshDaemon {
    store_path: std::path::PathBuf,
    connected_devices: ConnectedDevices,
    active_tasks: Arc<Mutex<HashSet<String>>>,
    check_interval: Duration,
}

impl RefreshDaemon {
    pub fn new() -> Self {
        Self {
            store_path: get_data_path().join("accounts.json"),
            connected_devices: Arc::new(Mutex::new(HashMap::new())),
            active_tasks: Arc::new(Mutex::new(HashSet::new())),
            check_interval: Duration::from_secs(60 * 3), // Check every 3 minutes
        }
    }

    pub fn connected_devices(&self) -> ConnectedDevices {
        self.connected_devices.clone()
    }

    pub fn spawn(self) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            loop {
                if let Err(e) = rt.block_on(self.check_and_refresh()) {
                    log::error!("Refresh daemon error: {}", e);
                    notify_rust::Notification::new()
                        .summary("Impactor")
                        .body(&format!("Failed to refresh: {}", e))
                        .show()
                        .ok();
                }

                thread::sleep(self.check_interval);
            }
        })
    }

    async fn check_and_refresh(&self) -> Result<(), String> {
        let store = AccountStore::load(&Some(self.store_path.clone()))
            .await
            .map_err(|e| format!("Failed to load account store: {}", e))?;

        let now = Utc::now();

        for (udid, refresh_device) in store.refreshes() {
            for app in &refresh_device.apps {
                if app.scheduled_refresh <= now {
                    // We check for active tasks here to prevent the background loop
                    // from even starting a wait if a manual refresh is already running.
                    if self.is_busy(udid) {
                        log::info!(
                            "Device {} is already being processed. Skipping this app for now.",
                            udid
                        );
                        continue;
                    }

                    log::info!("App at {:?} needs refresh for device {}", app.path, udid);

                    let device = self
                        .connected_devices
                        .lock()
                        .ok()
                        .and_then(|devices| devices.get(udid).cloned());

                    let Some(device) = device else {
                        log::debug!(
                            "App at {:?} is due for refresh on {}, but no matching connected device was found. Retrying in {} seconds.",
                            app.path,
                            udid,
                            self.check_interval.as_secs()
                        );
                        continue;
                    };

                    if let Err(e) = self.refresh_app(&store, refresh_device, app, &device).await {
                        log::error!("Error refreshing app: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    fn is_busy(&self, udid: &str) -> bool {
        self.active_tasks
            .lock()
            .map(|t| t.contains(udid))
            .unwrap_or(false)
    }

    pub async fn refresh_app(
        &self,
        store: &AccountStore,
        refresh_device: &RefreshDevice,
        app: &plume_store::RefreshApp,
        device: &Device,
    ) -> Result<(), String> {
        // Try to acquire the lock for this UDID.
        {
            let mut tasks = self
                .active_tasks
                .lock()
                .map_err(|_| "Failed to lock task registry")?;
            if tasks.contains(&device.udid) {
                log::warn!(
                    "Refresh already in progress for {}. Aborting duplicate.",
                    device.udid
                );
                return Ok(());
            }
            tasks.insert(device.udid.clone());
        }

        // lock is released when this function returns
        let _guard = RefreshGuard {
            udid: device.udid.clone(),
            tasks: self.active_tasks.clone(),
        };

        log::info!("Starting refresh for app at {:?}", app.path);

        notify_rust::Notification::new()
            .summary("Impactor")
            .body(&format!(
                "Started refreshing {} for {}",
                app.name.as_deref().unwrap_or("???"),
                &refresh_device.name
            ))
            .show()
            .ok();

        let account = store
            .get_account(&refresh_device.account)
            .ok_or_else(|| format!("Account {} not found", refresh_device.account))?;

        let session = DeveloperSession::new(
            account.adsid().clone(),
            account.xcode_gs_token().clone(),
            AnisetteConfiguration::default().set_configuration_path(get_data_path()),
        )
        .await
        .map_err(|e| format!("Failed to create session: {}", e))?;

        let teams_response = session
            .qh_list_teams()
            .await
            .map_err(|e| format!("Failed to list teams: {}", e))?;

        if teams_response.teams.is_empty() {
            return Err("No teams available for this account".to_string());
        }

        let team_id = if account.team_id().is_empty() {
            &teams_response.teams[0].team_id
        } else {
            account.team_id()
        };

        let identity_is_new = {
            let mut on_certificate_reset = crate::certificate_reset::confirm;
            let identity = CertificateIdentity::new_with_session(
                &session,
                get_data_path(),
                None,
                team_id,
                false,
                Some(&mut on_certificate_reset),
            )
            .await
            .map_err(|e| format!("Failed to create identity: {}", e))?;
            identity.new
        };

        let is_installed = if let Some(bundle_id) = app.bundle_id.as_deref() {
            device
                .is_app_installed(bundle_id)
                .await
                .map_err(|e| format!("Failed to check if app is installed: {}", e))?
        } else {
            false
        };

        // Determine if we need to reinstall:
        // - Mac devices always need reinstalling
        // - If the identity is new, we need to reinstall
        // - If the app is not installed, we need to reinstall
        // - If the app is installed and identity is not new, we can just update profiles
        let needs_reinstall = device.is_mac || identity_is_new || !is_installed;

        if needs_reinstall {
            self.resign_and_reinstall(app, device, &session, team_id)
                .await?;
        } else {
            log::info!(
                "Certificate exists and app is installed, updating provisioning profiles..."
            );
            self.update_provisioning_profiles(app, device, &session, team_id)
                .await?;
        }

        self.update_refresh_schedule(store, refresh_device, app)
            .await?;

        log::info!("Successfully refreshed app at {:?}", app.path);

        notify_rust::Notification::new()
            .summary("Impactor")
            .body(&format!(
                "Successfully refreshed {} for {}",
                app.name.as_deref().unwrap_or("???"),
                &refresh_device.name
            ))
            .show()
            .ok();

        Ok(())
    }

    async fn resign_and_reinstall(
        &self,
        app: &plume_store::RefreshApp,
        device: &Device,
        session: &DeveloperSession,
        team_id: &str,
    ) -> Result<(), String> {
        let platform = device.developer_platform();

        let team_id_string = team_id.to_string();
        session
            .qh_ensure_device(&team_id_string, &device.name, &device.udid, platform)
            .await
            .map_err(|e| format!("Failed to ensure device: {}", e))?;

        let bundle =
            Bundle::new(app.path.clone()).map_err(|e| format!("Failed to create bundle: {}", e))?;

        let options = SignerOptions {
            mode: SignerMode::Pem,
            ..Default::default()
        };

        let team_id_string = team_id.to_string();
        let mut on_certificate_reset = crate::certificate_reset::confirm;
        let signing_identity = CertificateIdentity::new_with_session(
            session,
            get_data_path(),
            None,
            &team_id_string,
            false,
            Some(&mut on_certificate_reset),
        )
        .await
        .map_err(|e| format!("Failed to create signing identity: {}", e))?;

        let mut signer = Signer::new(Some(signing_identity), options);

        signer
            .register_bundle(&bundle, session, &team_id.to_string(), true, platform)
            .await
            .map_err(|e| format!("Failed to register bundle: {}", e))?;

        signer
            .sign_bundle(&bundle)
            .await
            .map_err(|e| format!("Failed to sign bundle: {}", e))?;

        if !device.is_mac {
            device
                .install_app(&app.path, |_| async {})
                .await
                .map_err(|e| format!("Failed to install app: {}", e))?;
        } else {
            plume_utils::install_app_mac(&app.path)
                .await
                .map_err(|e| format!("Failed to install app on Mac: {}", e))?;
        }

        Ok(())
    }

    async fn update_provisioning_profiles(
        &self,
        app: &plume_store::RefreshApp,
        device: &Device,
        session: &DeveloperSession,
        team_id: &str,
    ) -> Result<(), String> {
        let bundle =
            Bundle::new(app.path.clone()).map_err(|e| format!("Failed to create bundle: {}", e))?;

        let options = SignerOptions {
            mode: SignerMode::Pem,
            ..Default::default()
        };

        let mut signer = Signer::new(None, options);

        signer
            .register_bundle(
                &bundle,
                session,
                &team_id.to_string(),
                true,
                device.developer_platform(),
            )
            .await
            .map_err(|e| format!("Failed to register bundle: {}", e))?;

        for provision in &signer.provisioning_files {
            device
                .install_profile(provision)
                .await
                .map_err(|e| format!("Failed to install profile: {}", e))?;
        }

        Ok(())
    }

    async fn update_refresh_schedule(
        &self,
        store: &AccountStore,
        refresh_device: &RefreshDevice,
        app: &plume_store::RefreshApp,
    ) -> Result<(), String> {
        let embedded_prov_path = app.path.join("embedded.mobileprovision");
        if !embedded_prov_path.exists() {
            return Err("embedded.mobileprovision not found".to_string());
        }

        let provision = MobileProvision::load_with_path(&embedded_prov_path)
            .map_err(|e| format!("Failed to load mobile provision: {}", e))?;

        let expiration_date = provision.expiration_date().clone();
        let scheduled_refresh = expiration_date
            .to_xml_format()
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap_or_else(|_| Utc::now() + chrono::Duration::days(4));
        let scheduled_refresh = scheduled_refresh - chrono::Duration::days(3);

        let mut store = store.clone();
        let mut updated_device = refresh_device.clone();

        if let Some(existing_app) = updated_device.apps.iter_mut().find(|a| a.path == app.path) {
            existing_app.scheduled_refresh = scheduled_refresh;
        }

        store
            .add_or_update_refresh_device_sync(updated_device)
            .map_err(|e| format!("Failed to update refresh schedule: {}", e))?;

        log::info!("Next refresh scheduled for: {}", scheduled_refresh);

        Ok(())
    }
}

pub fn spawn_refresh_daemon() -> (thread::JoinHandle<()>, ConnectedDevices) {
    let daemon = RefreshDaemon::new();
    let devices = daemon.connected_devices();
    let handle = daemon.spawn();
    (handle, devices)
}
