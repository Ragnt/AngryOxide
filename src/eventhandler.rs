use byteorder::{ByteOrder, LE};
use crossterm::event::{poll, Event, KeyCode, KeyEventKind, MouseEventKind};

use std::time::{Duration, UNIX_EPOCH};
use std::{
    sync::{
        self,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
        Arc, Mutex,
    },
    thread,
    time::SystemTime,
};
use uuid::Uuid;

pub enum EventType {
    Key(Event),
    Tick,
}

pub struct OxideEvent {
    pub event_type: EventType,
}

pub struct EventHandler {
    handle: Option<thread::JoinHandle<()>>,
    alive: sync::Arc<AtomicBool>,
    tx: Sender<EventType>,
    rx: Receiver<EventType>,
}

impl EventHandler {
    pub fn new() -> EventHandler {
        let (tx, rx) = mpsc::channel();

        EventHandler {
            handle: None,
            alive: Arc::new(AtomicBool::new(false)),
            tx,
            rx,
        }
    }

    pub fn get(&mut self) -> Option<EventType> {
        if let Ok(event) = self.rx.try_recv() {
            return Some(event);
        }
        None
    }

    pub fn start(&mut self) {
        self.alive.store(true, Ordering::SeqCst);
        let alive = self.alive.clone();
        let tx = self.tx.clone();

        self.handle = Some(thread::spawn(move || {
            while alive.load(Ordering::SeqCst) {
                if poll(Duration::from_millis(50)).unwrap() {
                    let event = crossterm::event::read().unwrap();
                    if let Event::Key(key) = event {
                        if key.kind == KeyEventKind::Press {
                            match key.code {
                                KeyCode::Char('d') => tx.send(EventType::Key(event)),
                                KeyCode::Char('a') => tx.send(EventType::Key(event)),
                                KeyCode::Char('W') => tx.send(EventType::Key(event)),
                                KeyCode::Char('w') => tx.send(EventType::Key(event)),
                                KeyCode::Char('s') => tx.send(EventType::Key(event)),
                                KeyCode::Char('S') => tx.send(EventType::Key(event)),
                                KeyCode::Char('q') => tx.send(EventType::Key(event)),
                                KeyCode::Char(' ') => tx.send(EventType::Key(event)),
                                KeyCode::Char('e') => tx.send(EventType::Key(event)),
                                KeyCode::Char('r') => tx.send(EventType::Key(event)),
                                KeyCode::Char('n') => tx.send(EventType::Key(event)),
                                KeyCode::Char('N') => tx.send(EventType::Key(event)),
                                KeyCode::Char('y') => tx.send(EventType::Key(event)),
                                KeyCode::Char('Y') => tx.send(EventType::Key(event)),
                                KeyCode::Char('c') => tx.send(EventType::Key(event)),
                                KeyCode::Char('C') => tx.send(EventType::Key(event)),
                                _ => Ok({}),
                            };
                        }
                    } else if let Event::Mouse(mouse) = event {
                        match mouse.kind {
                            MouseEventKind::ScrollDown => tx.send(EventType::Key(event)),
                            MouseEventKind::ScrollUp => tx.send(EventType::Key(event)),
                            _ => Ok({}),
                        };
                    }
                }
                tx.send(EventType::Tick);
            }
        }));
    }

    pub fn stop(&mut self) {
        self.alive.store(false, Ordering::SeqCst);
        self.handle
            .take()
            .expect("Called stop on non-running thread")
            .join()
            .expect("Could not join spawned thread");

        println!("Stopped PCAPNG Thread");
    }
}
