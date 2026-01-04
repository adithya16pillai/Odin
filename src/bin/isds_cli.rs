use std::path::PathBuf;
use structopt::StructOpt;

use odin::config::Config;

/// Intrusion Detection System (ISDS) Command Line Interface
#[derive(StructOpt, Debug)]
#[structopt(name = "isds", about = "Intrusion Detection System CLI")]
pub enum Cli {
    /// Run the daemon
    Daemon {
        /// Path to configuration file
        #[structopt(short, long, default_value = "config.toml")]
        config: PathBuf,
    },
    /// Generate a default configuration file
    Config {
        /// Output path for the configuration file
        #[structopt(short, long, default_value = "config.toml")]
        output: PathBuf,
    },
    /// Parse and display log events from a file
    Parse {
        /// Path to log file
        #[structopt(short, long)]
        file: PathBuf,
        /// Number of lines to parse
        #[structopt(short, long, default_value = "10")]
        lines: usize,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::from_args();

    match cli {
        Cli::Daemon { config } => {
            println!("Starting ISDS daemon with config: {:?}", config);
            // In a real implementation, this would start the daemon
            // For now, just show that the config file exists
            if config.exists() {
                let _config = Config::from_file(&config)?;
                println!("Configuration loaded successfully");
                println!("Use 'isds-daemon' binary to run the daemon");
            } else {
                eprintln!("Configuration file not found: {:?}", config);
                eprintln!("Run 'isds config' to generate a default configuration");
                std::process::exit(1);
            }
        }
        Cli::Config { output } => {
            let config = Config::default();
            config.to_file(&output)?;
            println!("Default configuration written to: {:?}", output);
        }
        Cli::Parse { file, lines } => {
            if !file.exists() {
                eprintln!("File not found: {:?}", file);
                std::process::exit(1);
            }

            let mut tailer = odin::input::FileTailer::new(file);
            tailer.initialize()?;
            
            let events = tailer.read_events()?;
            let display_count = std::cmp::min(lines, events.len());
            
            println!("Parsed {} event(s) (showing {}):\n", events.len(), display_count);
            for event in events.iter().take(display_count) {
                println!("  User: {}, IP: {}, Type: {}, Timestamp: {}", 
                    event.user, 
                    event.ip_address, 
                    event.event_type,
                    event.timestamp
                );
            }
        }
    }

    Ok(())
}

