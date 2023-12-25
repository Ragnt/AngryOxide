use chrono::{DateTime, Utc};
use std::{collections::VecDeque, fmt};

// Define an enum for message types

#[derive(Clone)]
pub enum MessageType {
    Error,
    Warning,
    Info,
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message_type_str = match self {
            MessageType::Error => "Error",
            MessageType::Warning => "Warning",
            MessageType::Info => "Info",
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
}

impl MessageLog {
    pub fn new() -> Self {
        MessageLog {
            messages: Vec::new(), // No capacity needed
        }
    }

    pub fn add_message(&mut self, message: StatusMessage) {
        self.messages.push(message);
    }

    pub fn get_all_messages(&self) -> Vec<StatusMessage> {
        self.messages.clone()
    }

    pub fn size(&self) -> usize {
        self.messages.len()
    }
}
