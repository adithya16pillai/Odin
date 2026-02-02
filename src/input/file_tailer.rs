use crate::models::LogEvent;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::time::Duration;
use std::net::IpAddr;
use std::str::FromStr;

/// Tail a log file and parse log events
pub struct FileTailer {
    file_path: PathBuf,
    reader: Option<BufReader<File>>,
    file_position: u64,
}

impl FileTailer {
    /// Create a new file tailer
    pub fn new(file_path: PathBuf) -> Self {
        FileTailer {
            file_path,
            reader: None,
            file_position: 0,
        }
    }

    /// Initialize the file reader
    pub fn initialize(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let file = File::open(&self.file_path)?;
        let mut reader = BufReader::new(file);
        
        // Seek to end of file to start tailing
        reader.seek(SeekFrom::End(0))?;
        self.file_position = reader.stream_position()?;
        self.reader = Some(reader);
        
        Ok(())
    }

    /// Read new log events from the file
    pub fn read_events(&mut self) -> Result<Vec<LogEvent>, Box<dyn std::error::Error>> {
        if self.reader.is_none() {
            self.initialize()?;
        }

        let reader = self.reader.as_mut().ok_or("Reader not initialized")?;
        let mut events = Vec::new();

        // Read all available lines
        loop {
            let mut line = String::new();
            let bytes_read = reader.read_line(&mut line)?;
            
            if bytes_read == 0 {
                break; // EOF
            }

            self.file_position += bytes_read as u64;

            // Try to parse the line as a log event
            if let Ok(event) = Self::parse_log_line(&line) {
                events.push(event);
            }
        }

        Ok(events)
    }

    /// Parse a log line into a LogEvent
    /// This is a basic parser - in production, you'd want a more robust parser
    /// that handles different log formats (syslog, auth.log, etc.)
    fn parse_log_line(line: &str) -> Result<LogEvent, Box<dyn std::error::Error>> {
        // Basic SSH log format parser (simplified)
        // Example: "Jan 1 12:00:00 hostname sshd[1234]: Accepted publickey for user from 192.168.1.1"
        
        // Try to extract IP address
        let ip_pattern = regex::Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")?;
        let ip_addr = if let Some(cap) = ip_pattern.find(line) {
            IpAddr::from_str(cap.as_str())?
        } else {
            IpAddr::from_str("0.0.0.0")? // Default if not found
        };

        // Try to extract username (after "for")
        let user = if let Some(pos) = line.find("for ") {
            let after_for = &line[pos + 4..];
            if let Some(end_pos) = after_for.find(' ') {
                after_for[..end_pos].to_string()
            } else if let Some(end_pos) = after_for.find(" from") {
                after_for[..end_pos].to_string()
            } else {
                "unknown".to_string()
            }
        } else {
            "unknown".to_string()
        };

        // Get current timestamp (in a real implementation, parse from log line)
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        // Determine event type
        let event_type = if line.contains("Accepted") || line.contains("Successful") {
            "SSH_LOGIN".to_string()
        } else if line.contains("Failed") || line.contains("Invalid") {
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

    /// Check if the file still exists and is readable
    pub fn is_valid(&self) -> bool {
        self.file_path.exists()
    }
}

// ============================================
// Async File Tailer
// ============================================

use tokio::fs::File as AsyncFile;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader as AsyncBufReader};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration as TokioDuration};

/// Async version of FileTailer for use with tokio
pub struct AsyncFileTailer {
    file_path: PathBuf,
}

impl AsyncFileTailer {
    /// Create a new async file tailer
    pub fn new(file_path: PathBuf) -> Self {
        AsyncFileTailer { file_path }
    }

    /// Run the file tailer, sending events through the channel
    ///
    /// This method runs indefinitely until the channel is closed or
    /// an unrecoverable error occurs.
    pub async fn run(
        &mut self,
        tx: mpsc::Sender<LogEvent>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let file = AsyncFile::open(&self.file_path).await?;
        let mut reader = AsyncBufReader::new(file);

        // Seek to end of file to start tailing
        reader.seek(std::io::SeekFrom::End(0)).await?;

        log::info!("Async file tailer started for {:?}", self.file_path);

        loop {
            let mut line = String::new();

            match reader.read_line(&mut line).await {
                Ok(0) => {
                    // EOF - wait for more data
                    sleep(TokioDuration::from_millis(100)).await;
                }
                Ok(_) => {
                    // Parse the line and send the event
                    if let Ok(event) = Self::parse_log_line(&line) {
                        if tx.send(event).await.is_err() {
                            log::info!("Channel closed, stopping file tailer");
                            break;
                        }
                    }
                }
                Err(e) => {
                    log::error!("Error reading file: {}", e);
                    sleep(TokioDuration::from_secs(1)).await;
                }
            }
        }

        Ok(())
    }

    /// Parse a log line into a LogEvent (same logic as sync version)
    fn parse_log_line(line: &str) -> Result<LogEvent, Box<dyn std::error::Error + Send + Sync>> {
        // Try to extract IP address
        let ip_pattern = regex::Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")?;
        let ip_addr = if let Some(cap) = ip_pattern.find(line) {
            IpAddr::from_str(cap.as_str())?
        } else {
            IpAddr::from_str("0.0.0.0")?
        };

        // Try to extract username (after "for")
        let user = if let Some(pos) = line.find("for ") {
            let after_for = &line[pos + 4..];
            if let Some(end_pos) = after_for.find(' ') {
                after_for[..end_pos].to_string()
            } else if let Some(end_pos) = after_for.find(" from") {
                after_for[..end_pos].to_string()
            } else {
                "unknown".to_string()
            }
        } else {
            "unknown".to_string()
        };

        // Get current timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        // Determine event type
        let event_type = if line.contains("Accepted") || line.contains("Successful") {
            "SSH_LOGIN".to_string()
        } else if line.contains("Failed") || line.contains("Invalid") {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_log_line() {
        let line = "Jan 1 12:00:00 hostname sshd[1234]: Accepted publickey for alice from 192.168.1.100 port 12345";
        let event = FileTailer::parse_log_line(line).unwrap();
        assert_eq!(event.user, "alice");
        assert_eq!(event.ip_address.to_string(), "192.168.1.100");
        assert_eq!(event.event_type, "SSH_LOGIN");
    }
}

