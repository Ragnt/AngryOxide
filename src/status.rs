use chrono::{DateTime, Utc};
use std::fmt;

// Define an enum for message types

#[derive(Clone)]
pub enum MessageType {
    Error,
    Warning,
    Info,
    Priority,
    Status,
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message_type_str = match self {
            MessageType::Error => "Error",
            MessageType::Warning => "Warning",
            MessageType::Info => "Info",
            MessageType::Priority => "Priority",
            MessageType::Status => "Status",
        };
        write!(f, "{}", message_type_str)
    }
}

impl MessageType {
    pub fn to_str(&self) -> String {
        match self {
            MessageType::Error => "Error".to_owned(),
            MessageType::Warning => "Warning".to_owned(),
            MessageType::Info => "Info".to_owned(),
            MessageType::Priority => "Priority".to_owned(),
            MessageType::Status => "Status".to_owned(),
        }
    }
}

#[derive(Clone)]
pub struct StatusMessage {
    pub timestamp: DateTime<Utc>,
    pub message_type: MessageType,
    pub content: String,
}

impl StatusMessage {
    pub fn new(message_type: MessageType, content: String) -> Self {
        StatusMessage {
            timestamp: Utc::now(),
            message_type,
            content,
        }
    }
}

pub struct MessageLog {
    messages: Vec<StatusMessage>,
    headless: bool,
    max_size: usize, // New field to store the maximum number of messages
}

impl MessageLog {
    // Updated constructor to accept an optional max_size argument
    pub fn new(headless: bool, max_size: Option<usize>) -> Self {
        MessageLog {
            messages: Vec::new(),
            headless,
            max_size: max_size.unwrap_or(500), // Default to 500 if no value is provided
        }
    }

    pub fn add_message(&mut self, message: StatusMessage) {
        // Check if adding a new message would exceed the maximum size
        if self.messages.len() == self.max_size {
            // Remove the oldest message if the log is full
            self.messages.remove(0);
        }

        self.messages.push(message.clone());

        if self.headless {
            let color = match message.message_type {
                MessageType::Error => "\x1b[31m",
                MessageType::Warning => "\x1b[33m",
                MessageType::Info => "\x1b[0m",
                MessageType::Priority => "\x1b[32m",
                MessageType::Status => "\x1b[36m",
            };
            let white = "\x1b[0m";
            println!(
                "{}{} | {:^8} | {}{}",
                color,
                message.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                message.message_type.to_str(),
                message.content,
                white,
            )
        }
    }

    // Other methods remain unchanged
    pub fn get_all_messages(&self) -> Vec<StatusMessage> {
        self.messages.clone()
    }

    pub fn size(&self) -> usize {
        self.messages.len()
    }
}

