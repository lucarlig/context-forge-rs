// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::Mailbox,
    transport::smtp::authentication::Credentials,
};
use zeroize::Zeroizing;

pub(crate) struct Mailer {
    sender: Mailbox,
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

pub(crate) struct MailSettings {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) timeout: Duration,
    pub(crate) from_email: String,
    pub(crate) from_name: String,
    pub(crate) tls: MailTls,
    pub(crate) auth: Option<(String, Zeroizing<String>)>,
}

pub(crate) enum MailTls {
    Implicit,
    StartTls,
    Disabled,
}

impl Mailer {
    pub(crate) fn new(
        settings: MailSettings,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let sender = Mailbox::new(Some(settings.from_name), settings.from_email.parse()?);
        let transport = match settings.tls {
            MailTls::Implicit => AsyncSmtpTransport::<Tokio1Executor>::relay(&settings.host)?,
            MailTls::StartTls => {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&settings.host)?
            }
            MailTls::Disabled => {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(settings.host)
            }
        };
        let mut transport = transport
            .port(settings.port)
            .timeout(Some(settings.timeout));
        if let Some((username, password)) = settings.auth {
            transport = transport.credentials(Credentials::new(username, password.to_string()));
        }
        Ok(Self {
            sender,
            transport: transport.build(),
        })
    }

    pub(super) async fn send(&self, to: &str, subject: &str, body: String) -> bool {
        let Ok(to) = to.parse::<Mailbox>() else {
            return false;
        };
        let Ok(message) = Message::builder()
            .from(self.sender.clone())
            .to(to)
            .subject(subject)
            .body(body)
        else {
            return false;
        };
        if self.transport.send(message).await.is_err() {
            tracing::warn!("authentication email delivery failed");
            return false;
        }
        true
    }
}
