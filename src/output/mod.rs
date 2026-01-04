use crate::models::AnomalyReport;
use std::fs::OpenOptions;
use std::io::{Write, BufWriter};
use std::path::PathBuf;

/// Output handler for anomaly reports
pub struct OutputHandler {
    format: OutputFormat,
    writer: Option<Box<dyn Write + Send>>,
}

#[derive(Debug, Clone)]
pub enum OutputFormat {
    Json,
    Jsonl,
    Console,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" => OutputFormat::Json,
            "jsonl" => OutputFormat::Jsonl,
            "console" => OutputFormat::Console,
            _ => OutputFormat::Jsonl, // Default
        }
    }
}

impl OutputHandler {
    /// Create a new output handler
    pub fn new(format: OutputFormat, file_path: Option<PathBuf>) -> Result<Self, Box<dyn std::error::Error>> {
        let writer: Option<Box<dyn Write + Send>> = match (&format, file_path) {
            (OutputFormat::Console, _) => None,
            (_, Some(path)) => {
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?;
                Some(Box::new(BufWriter::new(file)))
            }
            (_, None) => None,
        };

        Ok(OutputHandler {
            format,
            writer,
        })
    }

    /// Write an anomaly report
    pub fn write_report(&mut self, report: &AnomalyReport) -> Result<(), Box<dyn std::error::Error>> {
        match &self.format {
            OutputFormat::Json => {
                let json = serde_json::to_string_pretty(report)?;
                self.write_output(&format!("{}\n", json))?;
            }
            OutputFormat::Jsonl => {
                let json = serde_json::to_string(report)?;
                self.write_output(&format!("{}\n", json))?;
            }
            OutputFormat::Console => {
                let output = format!(
                    "[{}] {} - User: {}, IP: {} -> {}, Severity: {}\n",
                    report.rule_name,
                    report.description,
                    report.user,
                    report.trusted_ip,
                    report.detected_ip,
                    report.severity
                );
                self.write_output(&output)?;
            }
        }
        Ok(())
    }

    fn write_output(&mut self, data: &str) -> Result<(), Box<dyn std::error::Error>> {
        match &mut self.writer {
            Some(writer) => {
                writer.write_all(data.as_bytes())?;
                writer.flush()?;
            }
            None => {
                print!("{}", data);
                use std::io::{self, Write};
                io::stdout().flush()?;
            }
        }
        Ok(())
    }

    /// Flush any buffered output
    pub fn flush(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(writer) = &mut self.writer {
            writer.flush()?;
        }
        Ok(())
    }
}

