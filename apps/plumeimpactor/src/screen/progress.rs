use std::sync::{Arc, Mutex, mpsc};

use iced::Element;
use iced::Length::Fill;
use iced::Task;
use iced::widget::{button, column, container, row, text};
use rust_i18n::t;

use crate::appearance;

type ProgressReceiver = Arc<Mutex<mpsc::Receiver<ProgressUpdate>>>;

/// A single update on the install progress channel.
///
/// `progress` keeps the existing `-1` (error) / `>= 100` (finished) sentinels; `determinate`
/// is a separate flag so a phase that reports no percentage of its own does not need a third
/// sentinel value layered onto `progress`.
#[derive(Debug, Clone)]
pub struct ProgressUpdate {
    pub status: String,
    pub progress: i32,
    pub determinate: bool,
}

impl ProgressUpdate {
    pub fn new(status: String, progress: i32) -> Self {
        Self {
            status,
            progress,
            determinate: true,
        }
    }

    pub fn indeterminate(status: String, progress: i32) -> Self {
        Self {
            status,
            progress,
            determinate: false,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum Message {
    InstallationProgress(ProgressUpdate),
    InstallationError(String),
    InstallationFinished,
    Back,
}

#[derive(Debug, Clone)]
pub struct ProgressScreen {
    pub status: String,
    pub progress: i32,
    pub determinate: bool,
    pub is_installing: bool,
    pub progress_rx: Option<ProgressReceiver>,
}

impl ProgressScreen {
    pub fn new() -> Self {
        Self {
            status: "Idle.".to_string(),
            progress: 0,
            determinate: true,
            is_installing: false,
            progress_rx: None,
        }
    }

    pub fn start_installation(&mut self, rx: ProgressReceiver) {
        self.is_installing = true;
        self.progress = 0;
        self.determinate = true;
        self.status = "Idle.".to_string();
        self.progress_rx = Some(rx);
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::InstallationProgress(update) => {
                let ProgressUpdate {
                    status,
                    progress,
                    determinate,
                } = update;
                self.status = status.clone();
                self.progress = progress;
                self.determinate = determinate;

                if progress == -1 {
                    self.progress_rx = None;
                    self.is_installing = false;

                    let error_msg = status.clone();
                    std::thread::spawn(move || {
                        rfd::MessageDialog::new()
                            .set_title(t!("progress_failed"))
                            .set_description(&error_msg)
                            .set_buttons(rfd::MessageButtons::Ok)
                            .show();
                    });
                } else if progress >= 100 {
                    self.progress_rx = None;
                    self.is_installing = false;

                    return Task::done(Message::InstallationFinished);
                }

                Task::none()
            }
            Message::InstallationError(error) => {
                self.progress = -1;
                self.status = format!("ERR: {}", error);
                self.progress_rx = None;
                self.is_installing = false;

                std::thread::spawn(move || {
                    rfd::MessageDialog::new()
                        .set_title(t!("progress_failed"))
                        .set_description(&error)
                        .set_buttons(rfd::MessageButtons::Ok)
                        .show();
                });

                Task::none()
            }
            Message::InstallationFinished => {
                self.progress = 100;
                self.status = t!("progress_finished").to_string();
                self.progress_rx = None;
                self.is_installing = false;

                Task::none()
            }
            Message::Back => Task::none(),
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let progress_bar = iced::widget::progress_bar(0.0..=100.0, self.progress as f32);

        let status_text = if self.determinate {
            format!("{}% - {}", self.progress, self.status)
        } else {
            self.status.clone()
        };

        let screen_content = column![
            text(t!("progress_installing_application")).size(14),
            text(status_text).size(14),
            progress_bar,
            container(text("")).height(Fill),
        ]
        .spacing(appearance::THEME_PADDING);

        column![
            container(screen_content).width(Fill).height(Fill),
            self.view_buttons()
        ]
        .into()
    }

    fn view_buttons(&self) -> Element<'_, Message> {
        container(row![
            button(appearance::icon_text(
                appearance::CHEVRON_BACK,
                t!("back"),
                None
            ))
            .on_press_maybe((!self.is_installing).then_some(Message::Back))
            .width(Fill)
            .style(appearance::s_button)
        ])
        .width(Fill)
        .into()
    }
}

impl Default for ProgressScreen {
    fn default() -> Self {
        Self::new()
    }
}
