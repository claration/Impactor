use std::collections::HashMap;

use iced::widget::{button, checkbox, column, container, pick_list, row, scrollable, text};
use iced::{Alignment, Element, Fill, Task};
use plume_store::AccountStore;
use rust_i18n::t;

use crate::appearance;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Team {
    pub name: String,
    pub id: String,
}

impl std::fmt::Display for Team {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name, self.id)
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    ShowLogin,
    SelectAccount(usize),
    RemoveAccount(usize),
    ExportP12,
    SelectTeam(String, String),
    FetchTeams(String),
    TeamsLoaded(String, Vec<Team>),
    ToggleAutoStart(bool),
    SelectLocale(Option<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocaleChoice {
    code: Option<String>,
}

impl LocaleChoice {
    fn system() -> Self {
        Self { code: None }
    }

    fn explicit(code: String) -> Self {
        Self { code: Some(code) }
    }

    fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }
}

impl std::fmt::Display for LocaleChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.code {
            None => write!(f, "{}", rust_i18n::t!("settings_system_language")),
            Some(code) => {
                let name = rust_i18n::t!("_language_name", locale = code);
                write!(f, "{}", name)
            }
        }
    }
}

#[derive(Debug)]
pub struct SettingsScreen {
    teams: HashMap<String, Vec<Team>>,
    loading_teams: Option<String>,
}

impl SettingsScreen {
    pub fn new() -> Self {
        Self {
            teams: HashMap::new(),
            loading_teams: None,
        }
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::FetchTeams(ref email) => {
                self.loading_teams = Some(email.clone());
                Task::none()
            }
            Message::TeamsLoaded(email, teams) => {
                self.teams.insert(email, teams);
                self.loading_teams = None;
                Task::none()
            }
            Message::ToggleAutoStart(_) => Task::none(),
            Message::SelectTeam(_, _) => Task::none(),
            Message::SelectLocale(_) => Task::none(),
            _ => Task::none(),
        }
    }

    pub fn view<'a>(
        &'a self,
        account_store: &'a Option<AccountStore>,
        selected_locale: &'a Option<String>,
    ) -> Element<'a, Message> {
        let Some(store) = account_store else {
            return column![text(t!("settings_loading_accounts"))]
                .spacing(appearance::THEME_PADDING)
                .padding(appearance::THEME_PADDING)
                .into();
        };

        let mut accounts: Vec<_> = store.accounts().iter().collect();
        accounts.sort_by_key(|(email, _)| *email);

        let selected_index = store
            .selected_account()
            .and_then(|acc| accounts.iter().position(|(e, _)| *e == acc.email()));

        let mut content = column![].spacing(appearance::THEME_PADDING);

        if !accounts.is_empty() {
            let account_list = accounts.iter().enumerate().fold(
                column![].spacing(appearance::THEME_PADDING),
                |content, (index, (email, account))| {
                    let marker = if Some(index) == selected_index {
                        "[✓] "
                    } else {
                        "[ ] "
                    };
                    let style = if Some(index) == selected_index {
                        appearance::p_button
                    } else {
                        appearance::s_button
                    };

                    let account_button = button(
                        text(format!("{}{}", marker, account.email()))
                            .size(appearance::THEME_FONT_SIZE)
                            .align_x(Alignment::Start),
                    )
                    .on_press(Message::SelectAccount(index))
                    .style(style)
                    .width(Fill);

                    let mut account_row = row![account_button].spacing(appearance::THEME_PADDING);

                    if Some(index) == selected_index {
                        let team_id = account.team_id();
                        let is_loading = self.loading_teams.as_ref() == Some(email);
                        let teams = self.teams.get(*email).cloned().unwrap_or_default();

                        let current_team = if !team_id.is_empty() {
                            teams.iter().find(|t| t.id == *team_id).cloned()
                        } else {
                            None
                        };

                        let placeholder = if is_loading {
                            t!("settings_select_teams").to_string()
                        } else if !team_id.is_empty() {
                            team_id.to_string()
                        } else {
                            t!("settings_loading_teams").to_string()
                        };

                        let email_owned = email.to_string();

                        let team_pick = pick_list(teams, current_team, move |selected: Team| {
                            Message::SelectTeam(email_owned.clone(), selected.id)
                        })
                        .placeholder(placeholder)
                        .on_open(Message::FetchTeams(email.to_string()))
                        .style(appearance::s_pick_list)
                        // Share the row evenly with the account button; otherwise a long
                        // team name would grow the picker and squeeze the account list.
                        .width(Fill);

                        account_row = account_row.push(team_pick);
                    }

                    content.push(account_row)
                },
            );

            content = content.push(container(scrollable(account_list)).height(Fill).style(
                |theme: &iced::Theme| container::Style {
                    border: iced::Border {
                        width: 1.0,
                        color: theme.palette().background.scale_alpha(0.5),
                        radius: appearance::THEME_CORNER_RADIUS.into(),
                    },
                    ..Default::default()
                },
            ));
        } else {
            content = content.push(text(t!("settings_no_accounts_yet")));
        }

        let auto_start_enabled = crate::startup::auto_start_enabled();
        content = content.push(self.view_auto_start_toggle(auto_start_enabled));
        content = content.push(self.view_language_picker(selected_locale));
        content = content.push(self.view_account_buttons(selected_index));

        content.into()
    }

    fn view_auto_start_toggle(&self, auto_start_enabled: bool) -> Element<'_, Message> {
        checkbox(auto_start_enabled)
            .label(t!("settings_launch_on_startup"))
            .on_toggle(Message::ToggleAutoStart)
            .into()
    }

    fn view_language_picker<'a>(
        &'a self,
        selected_locale: &'a Option<String>,
    ) -> Element<'a, Message> {
        let mut codes: Vec<String> = rust_i18n::available_locales!()
            .into_iter()
            .map(|s| s.to_string())
            .collect();
        codes.sort();

        let mut choices: Vec<LocaleChoice> = Vec::with_capacity(codes.len() + 1);
        choices.push(LocaleChoice::system());
        choices.extend(codes.into_iter().map(LocaleChoice::explicit));

        let current = match selected_locale {
            None => LocaleChoice::system(),
            Some(code) => LocaleChoice::explicit(code.clone()),
        };

        let picker = pick_list(choices, Some(current), |choice: LocaleChoice| {
            Message::SelectLocale(choice.code().map(|s| s.to_string()))
        })
        .style(appearance::s_pick_list);

        column![text(t!("settings_language")), picker]
            .spacing(appearance::THEME_PADDING)
            .into()
    }

    fn view_account_buttons(&self, selected_index: Option<usize>) -> Element<'_, Message> {
        let mut buttons = row![
            button(appearance::icon_text(
                appearance::PLUS,
                t!("settings_add_account"),
                None
            ))
            .on_press(Message::ShowLogin)
            .style(appearance::s_button)
        ]
        .spacing(appearance::THEME_PADDING);

        if let Some(index) = selected_index {
            buttons = buttons
                .push(
                    button(appearance::icon_text(
                        appearance::MINUS,
                        t!("settings_remove_account"),
                        None,
                    ))
                    .on_press(Message::RemoveAccount(index))
                    .style(appearance::s_button),
                )
                .push(
                    button(appearance::icon_text(
                        appearance::SHARE,
                        t!("settings_export_p12"),
                        None,
                    ))
                    .on_press(Message::ExportP12)
                    .style(appearance::s_button),
                );
        }

        buttons.align_y(Alignment::Center).into()
    }
}
