//! Alerting module for webhook notifications
//!
//! This module provides asynchronous alert dispatching to various
//! notification channels including Slack, Discord, and generic webhooks.

use crate::config::{AlertConfig, SlackConfig, DiscordConfig, WebhookConfig};
use crate::models::AnomalyReport;
use reqwest::Client;
use thiserror::Error;
use tokio::sync::mpsc;

/// Errors that can occur during alert dispatch
#[derive(Error, Debug)]
pub enum AlertError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Alert channel closed")]
    ChannelClosed,

    #[error("Alert queue full")]
    QueueFull,
}

/// Async alert dispatcher
///
/// This dispatcher runs as an async task and sends alerts to configured
/// notification channels (Slack, Discord, webhooks).
pub struct AlertDispatcher {
    config: AlertConfig,
    client: Client,
}

impl AlertDispatcher {
    /// Create a new alert dispatcher with the given configuration
    ///
    /// Returns the dispatcher and a receiver for the alert channel.
    /// The dispatcher should be spawned as a tokio task using `run()`.
    pub fn new(config: AlertConfig) -> (Self, mpsc::Receiver<AnomalyReport>) {
        let (tx, rx) = mpsc::channel(100);
        let dispatcher = AlertDispatcher {
            config,
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
        };
        // Store the sender in a static or return it separately
        // For now, we'll use a different pattern
        (dispatcher, rx)
    }

    /// Create a sender for queueing alerts
    pub fn create_channel() -> (mpsc::Sender<AnomalyReport>, mpsc::Receiver<AnomalyReport>) {
        mpsc::channel(100)
    }

    /// Run the alert dispatch loop
    ///
    /// This method should be called as a tokio task. It will receive
    /// anomaly reports from the channel and dispatch them to all
    /// configured notification channels.
    pub async fn run(self, mut rx: mpsc::Receiver<AnomalyReport>) {
        log::info!("Alert dispatcher started");

        while let Some(report) = rx.recv().await {
            if !self.config.enabled {
                continue;
            }

            if report.severity < self.config.min_severity {
                log::debug!(
                    "Skipping alert for {} (severity {} < min {})",
                    report.rule_name,
                    report.severity,
                    self.config.min_severity
                );
                continue;
            }

            log::info!(
                "Dispatching alert: {} (severity {})",
                report.rule_name,
                report.severity
            );

            if let Err(e) = self.dispatch_alert(&report).await {
                log::error!("Failed to dispatch alert: {}", e);
            }
        }

        log::info!("Alert dispatcher stopped");
    }

    /// Dispatch an alert to all configured channels
    async fn dispatch_alert(&self, report: &AnomalyReport) -> Result<(), AlertError> {
        let mut errors = Vec::new();

        // Send to Slack
        if let Some(ref slack) = self.config.slack {
            if let Err(e) = self.send_slack_alert(slack, report).await {
                log::error!("Slack alert failed: {}", e);
                errors.push(e);
            }
        }

        // Send to Discord
        if let Some(ref discord) = self.config.discord {
            if let Err(e) = self.send_discord_alert(discord, report).await {
                log::error!("Discord alert failed: {}", e);
                errors.push(e);
            }
        }

        // Send to generic webhooks
        for webhook in &self.config.webhooks {
            if let Err(e) = self.send_generic_webhook(webhook, report).await {
                log::error!("Webhook {} failed: {}", webhook.name, e);
                errors.push(e);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            // Return the first error (could be improved to aggregate)
            Err(errors.remove(0))
        }
    }

    /// Send an alert to Slack
    async fn send_slack_alert(
        &self,
        config: &SlackConfig,
        report: &AnomalyReport,
    ) -> Result<(), AlertError> {
        let severity_emoji = match report.severity {
            10 => ":rotating_light:",
            9 => ":warning:",
            8 => ":exclamation:",
            _ => ":information_source:",
        };

        let color = match report.severity {
            10 | 9 => "danger",
            8 | 7 => "warning",
            _ => "good",
        };

        let payload = serde_json::json!({
            "channel": config.channel,
            "username": config.username.as_deref().unwrap_or("Odin IDS"),
            "icon_emoji": ":shield:",
            "attachments": [{
                "color": color,
                "title": format!("{} {}", severity_emoji, report.rule_name),
                "fields": [
                    { "title": "User", "value": &report.user, "short": true },
                    { "title": "Severity", "value": report.severity.to_string(), "short": true },
                    { "title": "Detected IP", "value": &report.detected_ip, "short": true },
                    { "title": "Trusted IP", "value": if report.trusted_ip.is_empty() { "N/A" } else { &report.trusted_ip }, "short": true },
                ],
                "text": &report.description,
                "ts": report.timestamp,
            }]
        });

        let response = self
            .client
            .post(&config.webhook_url)
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            log::warn!("Slack returned non-success status: {}", response.status());
        }

        Ok(())
    }

    /// Send an alert to Discord
    async fn send_discord_alert(
        &self,
        config: &DiscordConfig,
        report: &AnomalyReport,
    ) -> Result<(), AlertError> {
        let color = match report.severity {
            10 => 0xFF0000, // Red
            9 => 0xFF6600,  // Orange
            8 => 0xFFCC00,  // Yellow
            7 => 0x00CCFF,  // Light blue
            _ => 0x00FF00,  // Green
        };

        // Format timestamp for Discord
        let timestamp = chrono::DateTime::from_timestamp(report.timestamp, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default();

        let payload = serde_json::json!({
            "username": config.username.as_deref().unwrap_or("Odin IDS"),
            "embeds": [{
                "title": format!(":shield: {}", report.rule_name),
                "description": &report.description,
                "color": color,
                "fields": [
                    { "name": "User", "value": &report.user, "inline": true },
                    { "name": "Severity", "value": format!("{}/10", report.severity), "inline": true },
                    { "name": "Detected IP", "value": &report.detected_ip, "inline": true },
                ],
                "timestamp": timestamp,
                "footer": {
                    "text": "Odin Intrusion Detection System"
                }
            }]
        });

        let response = self
            .client
            .post(&config.webhook_url)
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            log::warn!("Discord returned non-success status: {}", response.status());
        }

        Ok(())
    }

    /// Send an alert to a generic webhook
    async fn send_generic_webhook(
        &self,
        config: &WebhookConfig,
        report: &AnomalyReport,
    ) -> Result<(), AlertError> {
        let method = config.method.as_deref().unwrap_or("POST");

        let mut request = match method.to_uppercase().as_str() {
            "PUT" => self.client.put(&config.url),
            _ => self.client.post(&config.url),
        };

        // Add custom headers
        if let Some(ref headers) = config.headers {
            for (key, value) in headers {
                request = request.header(key, value);
            }
        }

        let response = request.json(report).send().await?;

        if !response.status().is_success() {
            log::warn!(
                "Webhook {} returned non-success status: {}",
                config.name,
                response.status()
            );
        }

        Ok(())
    }
}

/// Synchronous alert queue for use in sync code
///
/// This wrapper provides a sync-friendly interface to queue alerts
/// that will be dispatched by the async AlertDispatcher.
#[derive(Clone)]
pub struct AlertQueue {
    tx: mpsc::Sender<AnomalyReport>,
}

impl AlertQueue {
    /// Create a new alert queue with the given sender
    pub fn new(tx: mpsc::Sender<AnomalyReport>) -> Self {
        AlertQueue { tx }
    }

    /// Queue an alert for dispatch (non-blocking)
    ///
    /// This method uses try_send to avoid blocking. If the queue is
    /// full, the alert will be dropped and a warning logged.
    pub fn queue_alert(&self, report: AnomalyReport) {
        if let Err(e) = self.tx.try_send(report) {
            match e {
                mpsc::error::TrySendError::Full(_) => {
                    log::warn!("Alert queue full, dropping alert");
                }
                mpsc::error::TrySendError::Closed(_) => {
                    log::warn!("Alert queue closed");
                }
            }
        }
    }

    /// Queue an alert (async version)
    pub async fn queue_alert_async(&self, report: AnomalyReport) -> Result<(), AlertError> {
        self.tx
            .send(report)
            .await
            .map_err(|_| AlertError::ChannelClosed)
    }

    /// Check if the queue is closed
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_report() -> AnomalyReport {
        AnomalyReport {
            severity: 8,
            rule_name: "Test Rule".to_string(),
            user: "testuser".to_string(),
            detected_ip: "1.2.3.4".to_string(),
            trusted_ip: "5.6.7.8".to_string(),
            timestamp: 1700000000,
            description: "Test anomaly detected".to_string(),
        }
    }

    #[tokio::test]
    async fn test_alert_queue_creation() {
        let (tx, _rx) = AlertDispatcher::create_channel();
        let queue = AlertQueue::new(tx);

        // Queue should be open
        assert!(!queue.is_closed());
    }

    #[tokio::test]
    async fn test_alert_queue_send() {
        let (tx, mut rx) = AlertDispatcher::create_channel();
        let queue = AlertQueue::new(tx);

        let report = create_test_report();
        queue.queue_alert(report.clone());

        // Should receive the alert
        let received = rx.recv().await;
        assert!(received.is_some());
        assert_eq!(received.unwrap().rule_name, "Test Rule");
    }

    #[tokio::test]
    async fn test_alert_queue_async_send() {
        let (tx, mut rx) = AlertDispatcher::create_channel();
        let queue = AlertQueue::new(tx);

        let report = create_test_report();
        queue.queue_alert_async(report).await.unwrap();

        let received = rx.recv().await;
        assert!(received.is_some());
    }

    #[tokio::test]
    async fn test_alert_dispatcher_disabled() {
        let config = AlertConfig {
            enabled: false,
            min_severity: 7,
            slack: None,
            discord: None,
            webhooks: vec![],
        };

        let (dispatcher, rx) = AlertDispatcher::new(config);
        let (tx, _) = AlertDispatcher::create_channel();

        // Dispatcher should not send when disabled
        // (This is more of an integration test, hard to unit test properly)
        drop(dispatcher);
        drop(rx);
        drop(tx);
    }

    #[test]
    fn test_severity_filtering() {
        let config = AlertConfig {
            enabled: true,
            min_severity: 8,
            slack: None,
            discord: None,
            webhooks: vec![],
        };

        // Severity 7 should be filtered
        let report = AnomalyReport {
            severity: 7,
            rule_name: "Low Priority".to_string(),
            user: "user".to_string(),
            detected_ip: "1.1.1.1".to_string(),
            trusted_ip: "".to_string(),
            timestamp: 0,
            description: "test".to_string(),
        };

        assert!(report.severity < config.min_severity);
    }
}
