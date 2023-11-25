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

// Define a struct for the status message
pub struct StatusMessage {
    pub timestamp: DateTime<Utc>,  // Timestamp of the message
    pub message_type: MessageType, // Type of the message
    pub content: String,           // The specific message content
}

impl StatusMessage {
    // Constructor to create a new StatusMessage
    pub fn new(message_type: MessageType, content: String) -> Self {
        StatusMessage {
            timestamp: Utc::now(), // Set the current time as the timestamp
            message_type,
            content,
        }
    }
}

pub struct MessageLog {
    messages: VecDeque<StatusMessage>,
    capacity: usize, // Maximum number of messages to store
}

impl MessageLog {
    // Constructor for MessageLog
    pub fn new(capacity: usize) -> Self {
        MessageLog {
            messages: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    // Add a new message to the log
    pub fn add_message(&mut self, message: StatusMessage) {
        if self.messages.len() == self.capacity {
            self.messages.pop_front(); // Remove the oldest message if at capacity
        }
        self.messages.push_back(message);
    }

    // Get the most recent N messages
    pub fn get_recent_messages(&self, count: usize) -> Vec<&StatusMessage> {
        self.messages.iter().rev().take(count).collect()
    }
}
