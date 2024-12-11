use log::LevelFilter;
use crate::logger::{LoggerConfig, PacketLogger};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logger_initialization() {
        let config = LoggerConfig {
            log_to_console: true,
            log_to_file: false,
            file_path: None,
            log_level: LevelFilter::Info,
            max_log_file_size: None,
            backup_count: 0,
        };

        PacketLogger::new(config).init().expect("Logger initialization failed");

        log::info!("Info message");
        log::warn!("Warning message");
    }
}
