use crate::models::LogEvent;
use std::net::UdpSocket;
use std::time::Duration;

/// Syslog listener for receiving log events via UDP
pub struct SyslogListener {
    socket: UdpSocket,
    buffer: [u8; 1024],
}

impl SyslogListener {
    /// Create a new syslog listener bound to the given address
    pub fn new(address: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let socket = UdpSocket::bind(address)?;
        socket.set_read_timeout(Some(Duration::from_secs(1)))?;
        
        Ok(SyslogListener {
            socket,
            buffer: [0; 1024],
        })
    }

    /// Read a syslog message (non-blocking)
    pub fn read_message(&mut self) -> Result<Option<String>, Box<dyn std::error::Error>> {
        match self.socket.recv_from(&mut self.buffer) {
            Ok((size, _addr)) => {
                let message = String::from_utf8_lossy(&self.buffer[..size]).to_string();
                Ok(Some(message))
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock || 
                   e.kind() == std::io::ErrorKind::TimedOut {
                    Ok(None)
                } else {
                    Err(Box::new(e))
                }
            }
        }
    }

    /// Parse a syslog message into a LogEvent
    pub fn parse_syslog_message(message: &str) -> Result<LogEvent, Box<dyn std::error::Error>> {
        // Basic syslog parser
        // In production, you'd want a more robust parser
        
        use std::net::IpAddr;
        use std::str::FromStr;

        // Extract IP address
        let ip_pattern = regex::Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")?;
        let ip_addr = if let Some(cap) = ip_pattern.find(message) {
            IpAddr::from_str(cap.as_str())?
        } else {
            IpAddr::from_str("0.0.0.0")?
        };

        // Extract username
        let user = if let Some(pos) = message.find("for ") {
            let after_for = &message[pos + 4..];
            if let Some(end_pos) = after_for.find(' ') {
                after_for[..end_pos].to_string()
            } else {
                "unknown".to_string()
            }
        } else {
            "unknown".to_string()
        };

        // Get timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        // Determine event type
        let event_type = if message.contains("Accepted") || message.contains("Successful") {
            "SSH_LOGIN".to_string()
        } else if message.contains("Failed") || message.contains("Invalid") {
            "SSH_FAILED".to_string()
        } else {
            "UNKNOWN".to_string()
        };

        Ok(LogEvent {
            timestamp,
            user,
            ip_address: ip_addr,
            event_type,
        })
    }
}

// ============================================
// Async Syslog Listener
// ============================================

use tokio::net::UdpSocket as AsyncUdpSocket;
use tokio::sync::mpsc;

/// Async version of SyslogListener for use with tokio
pub struct AsyncSyslogListener {
    socket: AsyncUdpSocket,
}

impl AsyncSyslogListener {
    /// Create a new async syslog listener bound to the given address
    pub async fn new(address: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let socket = AsyncUdpSocket::bind(address).await?;
        Ok(AsyncSyslogListener { socket })
    }

    /// Run the syslog listener, sending events through the channel
    ///
    /// This method runs indefinitely until the channel is closed or
    /// an unrecoverable error occurs.
    pub async fn run(
        &mut self,
        tx: mpsc::Sender<LogEvent>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut buf = [0u8; 1024];

        log::info!("Async syslog listener started");

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((size, _addr)) => {
                    let message = String::from_utf8_lossy(&buf[..size]);

                    if let Ok(event) = SyslogListener::parse_syslog_message(&message) {
                        if tx.send(event).await.is_err() {
                            log::info!("Channel closed, stopping syslog listener");
                            break;
                        }
                    }
                }
                Err(e) => {
                    log::error!("Syslog recv error: {}", e);
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_syslog_message() {
        let message = "<34>Jan 1 12:00:00 hostname sshd[1234]: Accepted publickey for alice from 192.168.1.100";
        let event = SyslogListener::parse_syslog_message(message).unwrap();
        assert_eq!(event.user, "alice");
        assert_eq!(event.ip_address.to_string(), "192.168.1.100");
    }
}

