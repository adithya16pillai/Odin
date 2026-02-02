pub mod file_tailer;
pub mod syslog_listener;

pub use file_tailer::FileTailer;
pub use syslog_listener::SyslogListener;

// Async versions
pub use file_tailer::AsyncFileTailer;
pub use syslog_listener::AsyncSyslogListener;

