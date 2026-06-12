use std::io::Write;
use std::path::PathBuf;

use anyhow::{Ok, Result};
use clap::{Args, Subcommand};
use dialoguer::Select;

use plume_core::{AnisetteConfiguration, auth::Account, developer::DeveloperSession};
use plume_store::AccountStore;

use crate::get_data_path;

#[derive(Debug, Args)]
#[command(arg_required_else_help = true)]
pub struct AccountArgs {
    #[command(subcommand)]
    pub command: AccountCommands,
}

#[derive(Debug, Subcommand)]
#[command(arg_required_else_help = true)]
pub enum AccountCommands {
    /// Login to Apple Developer account
    Login(LoginArgs),
    /// Logout from Apple Developer account
    Logout,
    /// List all saved accounts
    List,
    /// Switch to a different account
    Switch(SwitchArgs),
    /// List certificates for a team
    Certificates(CertificatesArgs),
    /// List devices registered to the account
    Devices(DevicesArgs),
    /// Register a new device
    RegisterDevice(RegisterDeviceArgs),
    /// List all app IDs for a team
    AppIds(AppIdsArgs),
}

#[derive(Debug, Args)]
#[command(arg_required_else_help = true)]
pub struct LoginArgs {
    /// Apple ID email
    #[arg(short = 'u', long = "username", value_name = "EMAIL")]
    pub username: Option<String>,
    /// Password (will prompt if not provided)
    #[arg(short = 'p', long = "password", value_name = "PASSWORD")]
    pub password: Option<String>,
}

#[derive(Debug, Args)]
pub struct CertificatesArgs {
    /// Team ID to list certificates for
    #[arg(short = 't', long = "team", value_name = "TEAM_ID")]
    pub team_id: Option<String>,
    /// Filter by certificate type (development, distribution)
    #[arg(long = "type", value_name = "TYPE")]
    pub cert_type: Option<String>,
}

#[derive(Debug, Args)]
pub struct DevicesArgs {
    /// Team ID to list devices for
    #[arg(short = 't', long = "team", value_name = "TEAM_ID")]
    pub team_id: Option<String>,
    /// Filter by device platform (ios, tvos, watchos)
    #[arg(long = "platform", value_name = "PLATFORM")]
    pub platform: Option<String>,
}

#[derive(Debug, Args)]
pub struct RegisterDeviceArgs {
    /// Team ID to list devices for
    #[arg(short = 't', long = "team", value_name = "TEAM_ID")]
    pub team_id: Option<String>,
    /// Device UDID
    #[arg(short = 'u', long = "udid", value_name = "UDID", required = true)]
    pub udid: String,
    /// Device name
    #[arg(short = 'n', long = "name", value_name = "NAME", required = true)]
    pub name: String,
}

#[derive(Debug, Args)]
pub struct AppIdsArgs {
    /// Team ID to list app IDs for
    #[arg(short = 't', long = "team", value_name = "TEAM_ID")]
    pub team_id: Option<String>,
}

#[derive(Debug, Args)]
pub struct SwitchArgs {
    /// Email of the account to switch to
    #[arg(value_name = "EMAIL", required = true)]
    pub email: String,
}

pub async fn execute(args: AccountArgs) -> Result<()> {
    match args.command {
        AccountCommands::Login(login_args) => login(login_args).await,
        AccountCommands::Logout => logout().await,
        AccountCommands::List => list_accounts().await,
        AccountCommands::Switch(switch_args) => switch_account(switch_args).await,
        AccountCommands::Certificates(cert_args) => certificates(cert_args).await,
        AccountCommands::Devices(device_args) => devices(device_args).await,
        AccountCommands::RegisterDevice(register_args) => register_device(register_args).await,
        AccountCommands::AppIds(app_id_args) => app_ids(app_id_args).await,
    }
}

fn get_settings_path() -> PathBuf {
    get_data_path().join("accounts.json")
}

pub async fn get_authenticated_account() -> Result<DeveloperSession> {
    let settings_path = get_settings_path();
    let settings = AccountStore::load(&Some(settings_path.clone())).await?;

    let gsa_account = settings
        .selected_account()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No account selected. Please login first using 'plumesign account login'"
            )
        })?
        .clone();

    let anisette_config = AnisetteConfiguration::default().set_configuration_path(get_data_path());

    log::info!("Restoring session for {}...", gsa_account.email());

    let session = DeveloperSession::new(
        gsa_account.adsid().clone(),
        gsa_account.xcode_gs_token().clone(),
        anisette_config,
    )
    .await?;

    Ok(session)
}

async fn login(args: LoginArgs) -> Result<()> {
    let tfa_closure = |req: plume_core::auth::TwoFactorRequest| -> std::result::Result<
        plume_core::auth::TwoFactorAction,
        String,
    > {
        use plume_core::auth::{TwoFactorAction, TwoFactorMethod};

        let can_use_sms = !req.trusted_phone_numbers.is_empty();
        match req.method {
            TwoFactorMethod::Sms => log::info!("Enter the code sent via SMS: "),
            TwoFactorMethod::Device if can_use_sms => {
                log::info!("Enter the code sent to your device, or type 'sms' to receive it by text message: ")
            }
            TwoFactorMethod::Device => log::info!("Enter 2FA code: "),
        }

        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| e.to_string())?;
        let input = input.trim();

        if input.eq_ignore_ascii_case("sms") && can_use_sms {
            let id = if req.trusted_phone_numbers.len() == 1 {
                req.trusted_phone_numbers[0].id
            } else {
                let labels: Vec<String> = req
                    .trusted_phone_numbers
                    .iter()
                    .map(|p| format!("Phone ending in {}", p.last_two_digits))
                    .collect();
                let choice = Select::new()
                    .with_prompt("Send SMS to which number?")
                    .items(&labels)
                    .default(0)
                    .interact()
                    .map_err(|e| e.to_string())?;
                req.trusted_phone_numbers[choice].id
            };
            return std::result::Result::Ok(TwoFactorAction::SendSms(id));
        }

        std::result::Result::Ok(TwoFactorAction::SubmitCode(input.to_string()))
    };

    let anisette_config = AnisetteConfiguration::default().set_configuration_path(get_data_path());

    let username = if let Some(user) = args.username {
        user
    } else {
        log::info!("Enter Apple ID email: ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        input.trim().to_string()
    };

    let password = if let Some(pass) = args.password {
        pass
    } else {
        print!("Enter password: ");
        std::io::stdout().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        input.trim().to_string()
    };

    let login_closure = || -> std::result::Result<(String, String), String> {
        std::result::Result::Ok((username.clone(), password.clone()))
    };

    println!("Logging in...");
    let account = Account::login(login_closure, tfa_closure, anisette_config).await?;

    let settings_path = get_settings_path();
    let mut settings = AccountStore::load(&Some(settings_path.clone())).await?;
    settings
        .accounts_add_from_session(username, account)
        .await?;

    log::info!("Successfully logged in and account saved.");

    Ok(())
}

async fn logout() -> Result<()> {
    let settings_path = get_settings_path();
    let mut settings = AccountStore::load(&Some(settings_path.clone())).await?;

    let email = settings
        .selected_account()
        .ok_or_else(|| anyhow::anyhow!("No account currently logged in"))?
        .email()
        .clone();

    settings.accounts_remove(&email).await?;

    log::info!("Successfully logged out and removed account.");

    Ok(())
}

async fn certificates(args: CertificatesArgs) -> Result<()> {
    let session = get_authenticated_account().await?;

    let team_id = if args.team_id.is_none() {
        teams(&session).await?
    } else {
        args.team_id.unwrap()
    };

    let p = session.qh_list_certs(&team_id).await?.certificates;

    log::info!("{:#?}", p);

    Ok(())
}

async fn devices(args: DevicesArgs) -> Result<()> {
    let session = get_authenticated_account().await?;

    let team_id = if args.team_id.is_none() {
        teams(&session).await?
    } else {
        args.team_id.unwrap()
    };

    let p = session.qh_list_devices(&team_id).await?.devices;

    log::info!("{:#?}", p);

    Ok(())
}

async fn register_device(args: RegisterDeviceArgs) -> Result<()> {
    let session = get_authenticated_account().await?;

    let team_id = if args.team_id.is_none() {
        teams(&session).await?
    } else {
        args.team_id.unwrap()
    };

    let p = session
        .qh_add_device(&team_id, &args.name, &args.udid)
        .await?
        .device;

    log::info!("{:#?}", p);

    Ok(())
}

pub async fn teams(session: &DeveloperSession) -> Result<String> {
    let teams = session.qh_list_teams().await?.teams;

    if teams.len() == 1 {
        return Ok(teams[0].team_id.clone());
    }

    let team_names: Vec<String> = teams
        .iter()
        .map(|t| format!("{} ({})", t.name, t.team_id))
        .collect();

    let selection = Select::new().items(&team_names).default(0).interact()?;

    Ok(teams[selection].team_id.clone())
}

pub async fn app_ids(args: AppIdsArgs) -> Result<()> {
    let session = get_authenticated_account().await?;

    let team_id = if args.team_id.is_none() {
        teams(&session).await?
    } else {
        args.team_id.unwrap()
    };

    let p = session.v1_list_app_ids(&team_id, None).await?.data;

    log::info!("{:#?}", p);

    Ok(())
}

async fn list_accounts() -> Result<()> {
    let settings_path = get_settings_path();
    let settings = AccountStore::load(&Some(settings_path)).await?;

    let accounts = settings.accounts();

    if accounts.is_empty() {
        log::info!("No accounts found. Use 'account login' to add an account.");
        return Ok(());
    }

    let selected_email = settings.selected_account().map(|a| a.email().clone());

    log::info!("Saved accounts:");
    for (email, account) in accounts {
        let selected = if Some(email) == selected_email.as_ref() {
            "(selected)"
        } else {
            ""
        };

        log::info!(" [{}] {} {}", account.first_name(), email, selected);
    }

    Ok(())
}

async fn switch_account(args: SwitchArgs) -> Result<()> {
    let settings_path = get_settings_path();
    let mut settings = AccountStore::load(&Some(settings_path)).await?;

    if settings.get_account(&args.email).is_none() {
        return Err(anyhow::anyhow!(
            "Account '{}' not found. Use 'account list' to see available accounts.",
            args.email
        ));
    }

    settings.account_select(&args.email).await?;

    log::info!("Switched to account: {}", args.email);

    Ok(())
}
