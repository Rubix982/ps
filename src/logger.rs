use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use chrono::Local;
use log::{Level, LevelFilter, Metadata, Record, SetLoggerError};

/// Configuration for the logger
#[derive(Clone)]
pub struct LoggerConfig {
    pub log_to_console: bool,
    pub log_to_file: bool,
    pub file_path: Option<String>,
    pub log_level: LevelFilter,
    pub max_log_file_size: Option<u64>, // in bytes
    pub backup_count: usize,
}

/// A logger that supports console and file logging with rotation
pub struct PacketLogger {
    config: LoggerConfig,
    file_handle: Arc<Mutex<Option<File>>>,
}

impl PacketLogger {
    /// Create a new logger with the given configuration
    pub fn new(config: LoggerConfig) -> Self {
        let file_handle = if config.log_to_file {
            Arc::new(Mutex::new(Self::initialize_file(&config)))
        } else {
            Arc::new(Mutex::new(None))
        };

        Self { config, file_handle }
    }

    /// Initialize the log file and handle rotation if needed
    fn initialize_file(config: &LoggerConfig) -> Option<File> {
        if let Some(ref path) = config.file_path {
            if let Some(max_size) = config.max_log_file_size {
                Self::rotate_logs(path, config.backup_count, max_size).ok();
            }

            OpenOptions::new()
                .create(true)
                .write(true)
                .append(true)
                .open(path)
                .ok()
        } else {
            None
        }
    }

    /// Rotate log files when they exceed the specified size
    fn rotate_logs(base_path: &str, backup_count: usize, max_size: u64) -> io::Result<()> {
        let path = Path::new(base_path);

        if path.exists() && path.metadata()?.len() >= max_size {
            for i in (1..backup_count).rev() {
                let old_path = path.with_extension(format!("log.{}", i));
                let new_path = path.with_extension(format!("log.{}", i + 1));

                if old_path.exists() {
                    std::fs::rename(&old_path, &new_path)?;
                }
            }

            let first_backup = path.with_extension("log.1");
            std::fs::rename(path, &first_backup)?;
        }

        Ok(())
    }

    /// Format log messages with a timestamp and metadata
    fn format_message(&self, record: &Record) -> String {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        format!(
            "{} [{}] {}: {}\n",
            timestamp,
            record.level(),
            record.target(),
            record.args()
        )
    }

    /// Initialize the logger as the global logger
    pub fn init(self) -> Result<(), SetLoggerError> {
        log::set_max_level(self.config.log_level);
        log::set_boxed_logger(Box::new(self))
    }
}

impl log::Log for PacketLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.config.log_level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let log_message = self.format_message(record);

        // Log to console if enabled
        if self.config.log_to_console {
            match record.level() {
                Level::Error => eprintln!("{}", log_message.trim()),
                _ => println!("{}", log_message.trim()),
            }
        }

        // Log to file if enabled
        if self.config.log_to_file {
            if let Ok(mut file_handle) = self.file_handle.lock() {
                if let Some(file) = file_handle.as_mut() {
                    if file.write_all(log_message.as_bytes()).is_err() {
                        eprintln!("Failed to write to log file");
                    }
                }
            }
        }
    }

    fn flush(&self) {
        if let Ok(mut file_handle) = self.file_handle.lock() {
            if let Some(file) = file_handle.as_mut() {
                if file.flush().is_err() {
                    eprintln!("Failed to flush log file");
                }
            }
        }
    }
}

pub fn setup_logger() -> Result<(), Box<dyn std::error::Error>> {
    let config = LoggerConfig {
        log_to_console: true,
        log_to_file: true,
        file_path: Some("packet_sniffer.log".to_string()),
        log_level: LevelFilter::Debug,
        max_log_file_size: Some(10 * 1024 * 1024), // 10 MB
        backup_count: 3,
    };

    let logger = PacketLogger::new(config);
    logger.init()?;

    log::info!("Logger initialized");
    Ok(())
}
