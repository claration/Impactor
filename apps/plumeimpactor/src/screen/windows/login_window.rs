use iced::futures::SinkExt;
use iced::widget::{button, column, container, row, text, text_input};
use iced::{Alignment, Element, Fill, Task, window};
use plume_core::auth::{TwoFactorAction, TwoFactorMethod, TwoFactorRequest};
use plume_core::{AnisetteConfiguration, auth::Account};
use plume_store::{AccountStore, GsaAccount};
use rust_i18n::t;
use std::sync::mpsc as std_mpsc;

use crate::appearance;

#[derive(Debug, Clone)]
pub enum Message {
    EmailChanged(String),
    PasswordChanged(String),
    LoginSubmit,
    LoginCancel,
    LoginSuccess(GsaAccount),
    LoginFailed(String),
    TwoFactorCodeChanged(String),
    TwoFactorSubmit,
    TwoFactorCancel,
    SendCodeViaSms(u32),
    RequestTwoFactor {
        sms: bool,
        phones: Vec<(u32, String)>,
    },
}

pub struct LoginWindow {
    pub window_id: Option<window::Id>,
    email: String,
    password: String,
    two_factor_code: String,
    login_error: Option<String>,
    two_factor_error: Option<String>,
    is_logging_in: bool,
    show_two_factor: bool,
    two_factor_is_sms: bool,
    trusted_phones: Vec<(u32, String)>,
    two_factor_tx: Option<std_mpsc::Sender<Result<TwoFactorAction, String>>>,
}

impl LoginWindow {
    pub fn new() -> (Self, Task<Message>) {
        let (id, task) = window::open(window::Settings {
            size: iced::Size::new(400.0, 360.0),
            position: window::Position::Centered,
            resizable: false,
            decorations: true,
            ..Default::default()
        });

        (
            Self {
                window_id: Some(id),
                email: String::new(),
                password: String::new(),
                two_factor_code: String::new(),
                login_error: None,
                two_factor_error: None,
                is_logging_in: false,
                show_two_factor: false,
                two_factor_is_sms: false,
                trusted_phones: Vec::new(),
                two_factor_tx: None,
            },
            task.discard(),
        )
    }

    pub fn window_id(&self) -> Option<window::Id> {
        self.window_id
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::EmailChanged(email) => {
                self.email = email;
                Task::none()
            }
            Message::PasswordChanged(password) => {
                self.password = password;
                Task::none()
            }
            Message::LoginSubmit => {
                if self.email.trim().is_empty() || self.password.is_empty() {
                    self.login_error = Some("Email and password required".to_string());
                    return Task::none();
                }

                self.is_logging_in = true;
                self.show_two_factor = false;
                self.login_error = None;
                self.two_factor_error = None;
                let email = self.email.trim().to_string();
                let password = self.password.clone();
                self.password.clear();

                let (tx, rx) = std_mpsc::channel::<Result<TwoFactorAction, String>>();
                self.two_factor_tx = Some(tx);

                Task::run(Self::perform_login(email, password, rx), |msg| msg)
            }
            Message::RequestTwoFactor { sms, phones } => {
                self.show_two_factor = true;
                self.is_logging_in = false;
                self.two_factor_is_sms = sms;
                self.trusted_phones = phones;
                self.two_factor_code.clear();
                self.login_error = None;
                self.two_factor_error = None;
                Task::none()
            }
            Message::LoginCancel => {
                if let Some(id) = self.window_id {
                    self.two_factor_tx = None;
                    window::close(id)
                } else {
                    Task::none()
                }
            }
            Message::LoginSuccess(account) => {
                self.login_error = None;
                let path = crate::defaults::get_data_path().join("accounts.json");

                if let Ok(mut store) = tokio::runtime::Runtime::new()
                    .unwrap()
                    .block_on(async { AccountStore::load(&Some(path.clone())).await })
                {
                    let _ = store.accounts_add_sync(account);
                }

                if let Some(id) = self.window_id {
                    self.two_factor_tx = None;
                    window::close(id)
                } else {
                    Task::none()
                }
            }
            Message::LoginFailed(error) => {
                self.is_logging_in = false;
                if self.show_two_factor {
                    self.two_factor_error = Some(error);
                    self.login_error = None;
                } else {
                    self.two_factor_code.clear();
                    self.two_factor_error = None;
                    self.login_error = Some(error);
                }
                self.two_factor_tx = None;
                Task::none()
            }
            Message::TwoFactorCodeChanged(code) => {
                self.two_factor_code = code;
                self.two_factor_error = None;
                Task::none()
            }
            Message::TwoFactorSubmit => {
                let code = self.two_factor_code.trim().to_string();
                if code.is_empty() {
                    self.two_factor_error = Some("Code required".to_string());
                    return Task::none();
                }

                if let Some(tx) = &self.two_factor_tx {
                    let _ = tx.send(Ok(TwoFactorAction::SubmitCode(code)));
                }
                self.is_logging_in = true;
                Task::none()
            }
            Message::SendCodeViaSms(phone_id) => {
                if let Some(tx) = &self.two_factor_tx {
                    let _ = tx.send(Ok(TwoFactorAction::SendSms(phone_id)));
                }
                self.two_factor_error = None;
                self.is_logging_in = true;
                Task::none()
            }
            Message::TwoFactorCancel => {
                if let Some(tx) = self.two_factor_tx.take() {
                    let _ = tx.send(Err("Cancelled".to_string()));
                }
                if let Some(id) = self.window_id {
                    window::close(id)
                } else {
                    Task::none()
                }
            }
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        if self.show_two_factor {
            self.view_two_factor()
        } else {
            self.view_login()
        }
    }

    fn view_login(&self) -> Element<'_, Message> {
        let email_input = text_input("claration@riseup.net", &self.email)
            .on_input(Message::EmailChanged)
            .padding(8)
            .width(Fill);

        let mut password_input = text_input("password", &self.password)
            .on_input(Message::PasswordChanged)
            .secure(true)
            .padding(8)
            .width(Fill);
        if !self.is_logging_in {
            password_input = password_input.on_submit(Message::LoginSubmit);
        }

        let mut content = column![
            text(t!("login_only_set_to_fruit")).size(14),
            text(t!("login_email")).size(14),
            email_input,
            text(t!("login_password")).size(14),
            password_input,
        ]
        .spacing(appearance::THEME_PADDING)
        .align_x(Alignment::Start);

        if let Some(error) = &self.login_error {
            content = content.push(text(error).style(|_theme| text::Style {
                color: Some(iced::Color::from_rgb(1.0, 0.3, 0.3)),
            }));
        }

        let buttons = row![
            container(text("")).width(Fill),
            button(text(t!("cancel")))
                .on_press(Message::LoginCancel)
                .style(appearance::s_button),
            button(text(if self.is_logging_in {
                t!("login_loading")
            } else {
                t!("next")
            }))
            .on_press_maybe(if self.is_logging_in {
                None
            } else {
                Some(Message::LoginSubmit)
            })
            .style(appearance::p_button),
        ]
        .spacing(appearance::THEME_PADDING);

        content = content.push(container(text("")).width(Fill));
        content = content.push(buttons);

        container(content).padding(appearance::THEME_PADDING).into()
    }

    fn view_two_factor(&self) -> Element<'_, Message> {
        let mut code_input = text_input("Verification Code", &self.two_factor_code)
            .on_input(Message::TwoFactorCodeChanged)
            .padding(8)
            .width(Fill);
        if !self.is_logging_in {
            code_input = code_input.on_submit(Message::TwoFactorSubmit);
        }

        let description = if self.two_factor_is_sms {
            t!("login_two_fa_sms_desc")
        } else {
            t!("login_two_fa_desc")
        };

        let mut content = column![
            text(t!("login_two_fa")).size(20),
            text(description).size(14),
            code_input,
        ]
        .spacing(appearance::THEME_PADDING)
        .padding(appearance::THEME_PADDING)
        .align_x(Alignment::Start);

        if let Some(error) = &self.two_factor_error {
            content = content.push(text(error).style(|_theme| text::Style {
                color: Some(iced::Color::from_rgb(1.0, 0.3, 0.3)),
            }));
        }

        if !self.trusted_phones.is_empty() {
            content = content.push(text(t!("login_no_code")).size(13));
            for (id, last_two) in &self.trusted_phones {
                let label = if last_two.is_empty() {
                    t!("login_send_sms").to_string()
                } else {
                    format!("{} \u{2022}\u{2022}{}", t!("login_send_sms"), last_two)
                };
                let sms_button = button(text(label).size(13))
                    .on_press_maybe(if self.is_logging_in {
                        None
                    } else {
                        Some(Message::SendCodeViaSms(*id))
                    })
                    .style(appearance::s_button)
                    .padding(6);
                content = content.push(sms_button);
            }
        }

        let buttons = row![
            button(text(t!("cancel")))
                .on_press(Message::TwoFactorCancel)
                .style(appearance::s_button)
                .padding(8),
            button(text(if self.is_logging_in {
                t!("login_verifying")
            } else {
                t!("login_verify")
            }))
            .on_press_maybe(if self.is_logging_in {
                None
            } else {
                Some(Message::TwoFactorSubmit)
            })
            .style(appearance::p_button)
            .padding(8),
        ]
        .spacing(appearance::THEME_PADDING);

        content = content.push(buttons);
        container(content).padding(20).into()
    }

    fn perform_login(
        email: String,
        password: String,
        two_factor_rx: std_mpsc::Receiver<Result<TwoFactorAction, String>>,
    ) -> impl iced::futures::Stream<Item = Message> {
        iced::stream::channel(
            10,
            move |mut output: futures::channel::mpsc::Sender<Message>| async move {
                let (bridge_tx, mut bridge_rx) = tokio::sync::mpsc::unbounded_channel::<Message>();
                let email_clone = email.clone();

                std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap();

                    let anisette_config = AnisetteConfiguration::default()
                        .set_configuration_path(crate::defaults::get_data_path());

                    let account_result = rt.block_on(Account::login(
                        || Ok((email_clone.clone(), password.clone())),
                        |request: TwoFactorRequest| {
                            let phones = request
                                .trusted_phone_numbers
                                .iter()
                                .map(|p| (p.id, p.last_two_digits.clone()))
                                .collect();
                            let sms = request.method == TwoFactorMethod::Sms;
                            let _ = bridge_tx.send(Message::RequestTwoFactor { sms, phones });

                            match two_factor_rx.recv() {
                                Ok(result) => result,
                                Err(_) => Err("Two-factor authentication cancelled".to_string()),
                            }
                        },
                        anisette_config,
                    ));

                    let final_msg = match account_result {
                        Ok(account) => {
                            match rt.block_on(plume_store::account_from_session(
                                email_clone.clone(),
                                account,
                            )) {
                                Ok(gsa) => Message::LoginSuccess(gsa),
                                Err(e) => Message::LoginFailed(e.to_string()),
                            }
                        }
                        Err(e) => Message::LoginFailed(e.to_string()),
                    };
                    let _ = bridge_tx.send(final_msg);
                });

                while let Some(msg) = bridge_rx.recv().await {
                    let _ = output.send(msg).await;
                }
            },
        )
    }
}
