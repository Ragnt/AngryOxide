use chrono::{DateTime, Utc};
use std::{collections::VecDeque, fmt};

// Define an enum for message types
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
    messages: VecDeque<StatusMessage>,
    capacity: usize,
}

impl MessageLog {
    pub fn new(capacity: usize) -> Self {
        MessageLog {
            messages: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub fn add_message(&mut self, message: StatusMessage) {
        if self.messages.len() == self.capacity {
            self.messages.pop_front();
        }
        self.messages.push_back(message);
    }

    pub fn get_recent_messages(&self, count: usize) -> Vec<&StatusMessage> {
        self.messages.iter().rev().take(count).collect()
    }
}
