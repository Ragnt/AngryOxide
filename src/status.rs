use chrono::{DateTime, Utc};
use std::{collections::VecDeque, fmt};

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
}

impl MessageLog {
    pub fn new(headless: bool) -> Self {
        MessageLog {
            messages: Vec::new(), // No capacity needed
            headless,
        }
    }

    pub fn add_message(&mut self, message: StatusMessage) {
        self.messages.push(message.clone());
        if self.headless {
            let color = match message.message_type {
                MessageType::Error => "\x1b[31m",
                MessageType::Warning => "\x1b[33m",
                MessageType::Info => "",
                MessageType::Priority => "\x1b[32m",
                MessageType::Status => "\x1b[36m",
            };
            let white = "\x1b[0m";
            println!(
                "{}{} {} :: {}{}",
                color,
                message.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                message.message_type,
                message.content,
                white,
            )
        }
    }

    pub fn get_all_messages(&self) -> Vec<StatusMessage> {
        self.messages.clone()
    }

    pub fn size(&self) -> usize {
        self.messages.len()
    }
}
