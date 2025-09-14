use derive_setters::Setters;
use libwifi::frame::components::MacAddress;
use std::{io::Result, time::Instant};

// Helper function to set clipboard content for the current platform
fn set_clipboard_content(content: String) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use copypasta_ext::osc52::Osc52ClipboardContext;
        use copypasta_ext::prelude::*;
        use copypasta_ext::x11_bin::X11BinClipboardContext;

        let mut ctx = Osc52ClipboardContext::new_with(
            X11BinClipboardContext::new()
                .map_err(|e| anyhow::anyhow!("Failed to create X11 clipboard context: {:?}", e))?,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create OSC52 clipboard context: {:?}", e))?;
        ctx.set_contents(content)
            .map_err(|e| anyhow::anyhow!("Failed to set clipboard contents: {:?}", e))?;
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        // Use copypasta for macOS as well, or use pbcopy command
        use std::process::Command;
        Command::new("pbcopy")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child
                    .stdin
                    .as_mut()
                    .unwrap()
                    .write_all(content.as_bytes())?;
                child.wait().map(|_| ())
            })
            .map_err(|e| anyhow::anyhow!("Failed to set clipboard: {}", e))?;
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(anyhow::anyhow!("Unsupported platform for clipboard"))
    }
}

use crate::{
    advancedtable::{self, advtable::AdvTable},
    auth::{FourWayHandshake, HandshakeStorage},
    devices::{AccessPoint, Station, WiFiDeviceList},
    matrix::MatrixSnowstorm,
    snowstorm::Snowstorm,
    status::StatusMessage,
    tabbedblock::{
        tab::{Position, Tab},
        tabbedblock::TabbedBlock,
        tabbedblock::{BorderType, TabType},
    },
    util::epoch_to_string,
    OxideRuntime,
};

// Ratatui imports:
use ratatui::{
    buffer::Buffer,
    layout::{Alignment, Constraint, Direction, Layout, Margin, Rect, SegmentSize},
    prelude::{CrosstermBackend, Stylize, Terminal},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        Block, Borders, Cell, Clear, HighlightSpacing, Padding, Paragraph, Row, Scrollbar,
        ScrollbarOrientation, ScrollbarState, Table, TableState, Widget, Wrap,
    },
    Frame,
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MenuType {
    AccessPoints,
    Clients,
    Handshakes,
    Messages,
}

impl MenuType {
    pub fn index(&self) -> usize {
        *self as usize
    }

    pub fn get(usize: usize) -> MenuType {
        match usize {
            0 => MenuType::AccessPoints,
            1 => MenuType::Clients,
            2 => MenuType::Handshakes,
            3 => MenuType::Messages,
            _ => MenuType::AccessPoints,
        }
    }

    pub fn next(&self) -> MenuType {
        let mut idx = *self as usize;
        idx += 1;
        if idx > 3 {
            idx = 3
        }
        MenuType::get(idx)
    }

    pub fn previous(&self) -> MenuType {
        let mut idx = *self as usize;
        idx = idx.saturating_sub(1);
        MenuType::get(idx)
    }
}

pub struct UiState {
    // General State
    pub current_menu: MenuType,
    pub paused: bool,
    pub show_quit: bool,
    pub copy_short: bool,
    pub copy_long: bool,
    pub add_target: bool,
    pub set_autoexit: bool,
    pub show_keybinds: bool,

    // Geofencing
    pub geofenced: bool, // True means we are not getting data, false means we are
    pub geofence_distance: f64, // Distance from geofence center - the radius value. (how much closer you need to get)

    // AP Menu Options
    pub ap_sort: u8,
    pub ap_state: TableState,
    pub ap_table_data: WiFiDeviceList<AccessPoint>,
    pub ap_selected_item: Option<AccessPoint>,
    pub ap_sort_reverse: bool,

    // Client Menu Options
    pub sta_sort: u8,
    pub sta_state: TableState,
    pub sta_table_data: WiFiDeviceList<Station>,
    pub sta_selected_item: Option<Station>,
    pub sta_sort_reverse: bool,

    // Handshake Menu Options
    pub hs_sort: u8,
    pub hs_state: TableState,
    pub hs_table_data: HandshakeStorage,
    pub hs_selected_item: Option<FourWayHandshake>,
    pub hs_sort_reverse: bool,

    // Messages
    pub messages_sort: u8,
    pub messages_state: TableState,
    pub messages_table_data: Vec<StatusMessage>,
    pub messages_sort_reverse: bool,

    // Snowstorm
    pub ui_snowstorm: bool,
    pub snowstorm: Snowstorm,
    pub matrix_snowstorm: MatrixSnowstorm,
}

impl UiState {
    pub fn menu_next(&mut self) {
        if !self.show_quit {
            self.current_menu = self.current_menu.next();
        }
    }

    pub fn menu_back(&mut self) {
        if !self.show_quit {
            self.current_menu = self.current_menu.previous();
        }
    }

    pub fn sort_next(&mut self) {
        if !self.show_quit {
            match self.current_menu {
                MenuType::AccessPoints => self.ap_sort_next(),
                MenuType::Clients => self.cl_sort_next(),
                MenuType::Handshakes => self.hs_sort_next(),
                MenuType::Messages => (),
            };
        }
    }

    fn ap_sort_next(&mut self) {
        if !self.show_quit {
            self.ap_sort += 1;
            if self.ap_sort == 8 {
                self.ap_sort = 0;
            }
        }
    }

    fn cl_sort_next(&mut self) {
        if !self.show_quit {
            self.sta_sort += 1;
            if self.sta_sort == 5 {
                self.sta_sort = 0;
            }
        }
    }

    fn hs_sort_next(&mut self) {
        if !self.show_quit {
            self.hs_sort += 1;
            if self.hs_sort == 4 {
                self.hs_sort = 0;
            }
        }
    }

    fn messages_sort_next(&mut self) {
        if !self.show_quit {
            self.messages_sort += 1;
            if self.messages_sort == 2 {
                self.messages_sort = 0;
            }
        }
    }

    pub fn toggle_pause(&mut self) {
        if !self.show_quit {
            self.paused = !self.paused
        }
    }

    pub fn toggle_reverse(&mut self) {
        if !self.show_quit {
            let sort = match self.current_menu {
                MenuType::AccessPoints => &mut self.ap_sort_reverse,
                MenuType::Clients => &mut self.sta_sort_reverse,
                MenuType::Handshakes => &mut self.hs_sort_reverse,
                MenuType::Messages => &mut self.messages_sort_reverse,
            };
            *sort = !*sort;
        }
    }

    pub fn table_next_item(&mut self, table_size: usize) {
        if !self.show_quit {
            let state = match self.current_menu {
                MenuType::AccessPoints => &mut self.ap_state,
                MenuType::Clients => &mut self.sta_state,
                MenuType::Handshakes => &mut self.hs_state,
                MenuType::Messages => &mut self.messages_state,
            };
            let i = match state.selected() {
                Some(i) => {
                    if i >= table_size - 1 {
                        table_size - 1
                    } else {
                        i + 1
                    }
                }
                None => 0,
            };
            state.select(Some(i));
        }
    }

    pub fn table_next_item_big(&mut self, table_size: usize) {
        if !self.show_quit {
            let state = match self.current_menu {
                MenuType::AccessPoints => &mut self.ap_state,
                MenuType::Clients => &mut self.sta_state,
                MenuType::Handshakes => &mut self.hs_state,
                MenuType::Messages => &mut self.messages_state,
            };
            let i = match state.selected() {
                Some(mut i) => {
                    i += 10;
                    if i >= table_size - 1 {
                        table_size - 1
                    } else {
                        i
                    }
                }
                None => 0,
            };
            state.select(Some(i));
        }
    }

    pub fn table_previous_item(&mut self) {
        if !self.show_quit {
            let state: &mut TableState = match self.current_menu {
                MenuType::AccessPoints => &mut self.ap_state,
                MenuType::Clients => &mut self.sta_state,
                MenuType::Handshakes => &mut self.hs_state,
                MenuType::Messages => &mut self.messages_state,
            };
            let i = match state.selected() {
                Some(i) => i.saturating_sub(1),
                None => 0,
            };
            state.select(Some(i));
        }
    }

    pub fn table_previous_item_big(&mut self) {
        if !self.show_quit {
            let state: &mut TableState = match self.current_menu {
                MenuType::AccessPoints => &mut self.ap_state,
                MenuType::Clients => &mut self.sta_state,
                MenuType::Handshakes => &mut self.hs_state,
                MenuType::Messages => &mut self.messages_state,
            };
            let i = match state.selected() {
                Some(i) => i.saturating_sub(10),
                None => 0,
            };
            state.select(Some(i));
        }
    }
}

pub fn print_ui(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    oxide: &mut OxideRuntime,
    start_time: Instant,
    framerate: u64,
) -> Result<()> {
    terminal.hide_cursor()?;
    terminal.draw(|frame| {
        if frame.size().width < 105 || frame.size().height < 20 {
            let area = frame.size();

            let popup_area = Rect {
                x: area.width / 2 - 9,
                y: area.height / 2 - 1,
                width: 18,
                height: 3,
            };

            let popup = Popup::default()
                .content("Window too small")
                .style(Style::new().yellow().bold())
                .border_style(Style::new().red());
            frame.render_widget(popup, popup_area);
            return;
        }

        if oxide.ui_state.show_quit {
            create_quit_popup(frame, frame.size());
            return;
        }

        let full_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints(vec![
                Constraint::Length(3),
                Constraint::Min(1),
                Constraint::Length(1),
            ])
            .split(frame.size());

        // Create the top status bar
        create_status_bar(frame, full_layout[0], oxide, start_time, framerate);

        // Setup tabbed area
        let tabs = TabbedBlock::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .tab("Access Points")
            .tab("Stations")
            .tab("Handshakes")
            .tab(Tab::from("Status").alignment(Alignment::Right))
            .tab_type(TabType::Full)
            .tab_position(Position::Top)
            .select(oxide.ui_state.current_menu as usize);
        frame.render_widget(tabs.clone(), full_layout[1]);

        // Show tab content
        match oxide.ui_state.current_menu {
            MenuType::AccessPoints => create_ap_page(oxide, frame, tabs.inner(full_layout[1])),
            MenuType::Clients => create_sta_page(oxide, frame, tabs.inner(full_layout[1])),
            MenuType::Handshakes => create_hs_page(oxide, frame, tabs.inner(full_layout[1])),
            MenuType::Messages => create_status_page(oxide, frame, tabs.inner(full_layout[1])),
        }

        // Create bottom info bar
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::raw("| quit: ").style(Style::new()),
                Span::styled("[q]", Style::default().reversed()),
                Span::raw(" | change tab: ").style(Style::new()),
                Span::styled("[a]/[d]", Style::default().reversed()),
                Span::raw(" | pause: ").style(Style::new()),
                Span::styled("[space]", Style::default().reversed()),
                Span::raw(" | scroll: ").style(Style::new()),
                Span::styled("[w/W]/[s/S]", Style::default().reversed()),
                Span::raw(" | show keybinds: ").style(Style::new()),
                Span::styled("[k]", Style::default().reversed()),
                Span::raw(" |").style(Style::new()),
            ]))
            .alignment(Alignment::Center),
            full_layout[2],
        );

        if oxide.ui_state.show_keybinds {
            create_keybind_popup(frame, frame.size());
        } else if oxide.ui_state.geofenced {
            let area = frame.size();

            let popup_area = Rect {
                x: area.width / 2 - 25,
                y: area.height / 2 - 1,
                width: 50,
                height: 3,
            };

            let message = if oxide.ui_state.geofence_distance <= 0.0 {
                if !oxide.file_data.gps_source.get_gps().has_fix() {
                    "No GPS for Geofence".to_string()
                } else {
                    "Outside Geofence".to_string()
                }
            } else {
                format!(
                    "Outside Geofence: {:.1}m from border",
                    oxide.ui_state.geofence_distance
                )
            };
            let popup = Popup::default()
                .content(message)
                .style(Style::new().yellow().bold())
                .border_style(Style::new().red());
            frame.render_widget(popup, popup_area);
        }
    })?;
    Ok(())
}

fn create_quit_popup(frame: &mut Frame<'_>, area: Rect) {
    let popup_area = Rect {
        x: (area.width / 2) - 25,
        y: (area.height / 2) - 3,
        width: 50,
        height: 4,
    };

    let popup = Popup::default()
        .content("Are you sure you want to quit? \n[y/n]")
        .style(Style::new().yellow().bold())
        .border_style(Style::new().red());
    frame.render_widget(popup, popup_area);
}

fn create_keybind_popup(frame: &mut Frame<'_>, area: Rect) {
    let window_area = Rect {
        x: (area.width / 2) - 25,
        y: (area.height / 2) - 9,
        width: 50,
        height: 18,
    };

    frame.render_widget(Clear, window_area);
    let block = Block::new().borders(Borders::ALL);
    let hotkeys: Vec<Line<'_>> = vec![
        Line::from(vec![Span::styled("", Style::default().bold())]),
        Line::from(vec![Span::styled("KEY BINDS", Style::default().bold())]),
        Line::from(vec![Span::styled("", Style::default().bold())]),
        Line::from(vec![
            Span::raw("Sort Table").style(Style::new()),
            Span::raw(repeat_dot(33)).style(Style::new()),
            Span::styled("[e]", Style::default().reversed()),
        ]),
        Line::from(vec![
            Span::raw("Reverse Sorting").style(Style::new()),
            Span::raw(repeat_dot(28)).style(Style::new()),
            Span::styled("[r]", Style::default().reversed()),
        ]),
        Line::from(vec![
            Span::raw("Change Tabs").style(Style::new()),
            Span::raw(repeat_dot(28)).style(Style::new()),
            Span::styled("[a]/[d]", Style::default().reversed()),
        ]),
        Line::from(vec![
            Span::raw("Scroll Table").style(Style::new()),
            Span::raw(repeat_dot(27)).style(Style::new()),
            Span::styled("[w]/[s]", Style::default().reversed()),
        ]),
        Line::from(vec![
            Span::raw("Scroll Table (by 10)").style(Style::new()),
            Span::raw(repeat_dot(19)).style(Style::new()),
            Span::styled("[W]/[S]", Style::default().reversed()),
        ]),
        Line::from(vec![
            Span::raw("Pause UI").style(Style::new()),
            Span::raw(repeat_dot(31)).style(Style::new()),
            Span::styled("[space]", Style::default().reversed()),
        ]),
        Line::from(vec![
            Span::raw("Add Selected as Target").style(Style::new()),
            Span::raw(repeat_dot(21)).style(Style::new()),
            Span::styled("[t]", Style::default().reversed()),
        ]),
        Line::from(vec![
            Span::raw("Add Selected as Target (with autoexit)").style(Style::new()),
            Span::raw(repeat_dot(5)).style(Style::new()),
            Span::styled("[T]", Style::default().reversed()),
        ]),
        Line::from(vec![
            Span::raw("Copy Selected (SHORT)").style(Style::new()),
            Span::raw(repeat_dot(22)).style(Style::new()),
            Span::styled("[c]", Style::default().reversed()),
        ]),
        Line::from(vec![
            Span::raw("Copy Selected (LONG JSON)").style(Style::new()),
            Span::raw(repeat_dot(18)).style(Style::new()),
            Span::styled("[C]", Style::default().reversed()),
        ]),
        Line::from(vec![
            Span::raw("Toggle Channel Lock").style(Style::new()),
            Span::raw(repeat_dot(24)).style(Style::new()),
            Span::styled("[l]", Style::default().reversed()),
        ]),
        Line::from(vec![
            Span::raw("Toggle Target Channel Lock").style(Style::new()),
            Span::raw(repeat_dot(17)).style(Style::new()),
            Span::styled("[L]", Style::default().reversed()),
        ]),
        Line::from(vec![Span::styled("", Style::default().bold())]),
    ];

    let hotkey_para = Paragraph::new(hotkeys)
        .wrap(Wrap { trim: true })
        .block(block)
        .alignment(Alignment::Center);

    frame.render_widget(hotkey_para, window_area);
}

fn repeat_char(c: char, count: usize) -> String {
    std::iter::repeat_n(c, count).collect()
}

fn repeat_dot(count: usize) -> String {
    ".".repeat(count)
}

fn create_status_bar(
    frame: &mut Frame<'_>,
    top_area: Rect,
    oxide: &mut OxideRuntime,
    start_time: Instant,
    framerate: u64,
) {
    // Top Bar Layout
    let top_layout: std::rc::Rc<[Rect]> = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(vec![Constraint::Length(41), Constraint::Min(50)])
        .horizontal_margin(2)
        .split(top_area);

    let right_side_layout: std::rc::Rc<[Rect]> = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(vec![Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(top_layout[1]);

    // Logo
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::from("▄▄▄ ▄▄▄ ▄▄▄ ▄▄  ▄ ▄").style(Style::new().fg(Color::Red)),
                Span::from(" ▄▄▄ ▄ ▄ ▄▄▄ ▄▄  ▄▄▄").style(Style::new().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::from("█▄█ █ █ █ ▄ █▄▀ ▀▄▀").style(Style::new().fg(Color::Red)),
                Span::from(" █ █ ▀▄▀  █  █ █ █▄▄").style(Style::new().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::from("█ █ █ █ █▄█ █ █  █ ").style(Style::new().fg(Color::Red)),
                Span::from(" █▄█ █ █ ▄█▄ █▄▀ █▄▄").style(Style::new().fg(Color::White)),
            ]),
        ])
        .alignment(Alignment::Left),
        top_layout[0],
    );

    // Top Right
    let total_seconds = start_time.elapsed().as_secs();
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;
    let time_str = Line::from(format!(
        "Runtime: {:02}:{:02}:{:02}",
        hours, minutes, seconds
    ));
    let frame_count = Line::from(format!(
        "Frames #: {} | Rate: {}/s",
        oxide.counters.frame_count, framerate
    ));

    let flow = match oxide.ui_state.paused {
        true => Span::from("Paused").fg(Color::Red),
        false => match oxide.config.autoexit {
            true => Span::from("Running (Autoexit)").fg(Color::Yellow),
            false => Span::from("Running"),
        },
    };

    let dataflow = Line::from(vec![
        Span::from(format!("ERs: {}/s | UI: ", oxide.counters.empty_reads_rate,)),
        flow,
    ]);

    let status_text = vec![time_str, frame_count, dataflow];

    frame.render_widget(
        Paragraph::new(status_text).alignment(Alignment::Right),
        right_side_layout[1],
    );

    let interface_name = String::from_utf8(
        oxide.if_hardware.interface.name.clone().unwrap_or_default()
    );

    let mac_addr = MacAddress(
        oxide
            .if_hardware
            .interface
            .mac
            .clone()
            .unwrap_or_default()
            .try_into()
            .unwrap_or([0u8; 6])
    );

    // Top Left
    let interface = format!(
        "Interface: {}",
        interface_name.unwrap_or_else(|_| "unknown".to_string())
    );
    let mac: String = format!("MacAddr: {}", mac_addr);
    let channel = format!(
        "Frequency: {} {}",
        oxide
            .if_hardware
            .interface
            .frequency
            .frequency
            .map(|f| f.to_string())
            .unwrap_or_else(|| "N/A".to_string()),
        if oxide.ui_state.geofenced {
            "(GeoFenced)"
        } else if oxide.config.autohunt {
            "(Hunting)"
        } else if oxide.if_hardware.locked {
            "(Locked)"
        } else {
            ""
        }
    );

    let status_text = vec![interface.into(), mac.into(), channel.into()];

    // Top Right
    frame.render_widget(
        Paragraph::new(status_text).alignment(Alignment::Left),
        right_side_layout[0],
    );
}

fn create_ap_page(oxide: &mut OxideRuntime, frame: &mut Frame<'_>, area: Rect) {
    // Update the table data (from the real source) - This allows us to "pause the data"
    if !oxide.ui_state.paused {
        oxide.ui_state.ap_table_data = oxide.access_points.clone();
    }

    let (mut headers, rows) = oxide.ui_state.ap_table_data.get_table(
        oxide.ui_state.ap_state.selected(),
        oxide.ui_state.ap_sort,
        oxide.ui_state.ap_sort_reverse,
    );

    let selected_object = if let Some(sel_idx) = oxide.ui_state.ap_state.selected() {
        oxide
            .ui_state
            .ap_table_data
            .get_devices_sorted()
            .get(sel_idx)
    } else {
        None
    };

    oxide.ui_state.ap_selected_item = selected_object.cloned();

    if oxide.ui_state.copy_short {
        if let Some(ap) = selected_object {
            set_clipboard_content(ap.mac_address.to_string().to_string()).unwrap();
        }
        oxide.ui_state.copy_short = false;
    }
    if oxide.ui_state.copy_long {
        if let Some(ap) = selected_object {
            set_clipboard_content(ap.to_json_str().to_string()).unwrap();
        }
        oxide.ui_state.copy_long = false;
    }

    // Fill Rows
    let mut rows_vec: Vec<advancedtable::advtable::Row> = vec![];
    for (mut row, height) in rows {
        if oxide.ui_state.paused {
            row[4] = "Paused".to_owned();
        }
        rows_vec.push(advancedtable::advtable::Row::new(row).height(height));
    }

    // Set headers for sort
    let sort_icon = if oxide.ui_state.ap_sort_reverse {
        "▲"
    } else {
        "▼"
    };
    match oxide.ui_state.ap_sort {
        0 => headers[0] = format!("{} {}", headers[0], sort_icon),
        1 => headers[2] = format!("{} {}", headers[2], sort_icon),
        2 => headers[3] = format!("{} {}", headers[3], sort_icon),
        3 => headers[4] = format!("{} {}", headers[4], sort_icon),
        4 => headers[6] = format!("{} {}", headers[6], sort_icon),
        5 => headers[7] = format!("{} {}", headers[7], sort_icon),
        6 => headers[8] = format!("{} {}", headers[8], sort_icon),
        7 => headers[9] = format!("{} {}", headers[9], sort_icon),
        _ => headers[3] = format!("{} {}", headers[3], sort_icon),
    };

    let selected_style = Style::default().add_modifier(Modifier::REVERSED);

    let table: AdvTable<'_> = AdvTable::new(
        rows_vec.clone(),
        vec![
            Constraint::Length(5), // TGT
            Constraint::Min(16),   // Mac
            Constraint::Min(4),    // CH
            Constraint::Min(6),    // RSSI
            Constraint::Min(6),    // Last
            Constraint::Min(25),   // SSID
            Constraint::Min(9),    // Clients
            Constraint::Length(5), // Tx
            Constraint::Min(6),    // 4wHS
            Constraint::Min(7),    // PMKID
        ],
        area,
    )
    .segment_size(SegmentSize::EvenDistribution)
    .highlight_style(selected_style)
    .header(advancedtable::advtable::Row::new(headers).style(Style::new().bold()))
    .highlight_symbol(">> ")
    .highlight_spacing(advancedtable::advtable::HighlightSpacing::Always)
    .block(Block::default().borders(Borders::RIGHT));

    let select_area = table
        .clone()
        .selected_row_area(&mut oxide.ui_state.ap_state.clone());

    let scrollbar = Scrollbar::default()
        .orientation(ScrollbarOrientation::VerticalRight)
        .begin_symbol(Some("↑"))
        .end_symbol(Some("↓"));

    let mut scrollbar_state = ScrollbarState::new(oxide.get_current_menu_len())
        .position(oxide.ui_state.ap_state.selected().unwrap_or(0));

    frame.render_stateful_widget(table, area, &mut oxide.ui_state.ap_state);
    frame.render_stateful_widget(
        scrollbar,
        area.inner(&Margin {
            vertical: 0,
            horizontal: 0,
        }),
        &mut scrollbar_state,
    );

    if let Some(area) = select_area {
        if let Some(ap) = selected_object {
            let block_area = Rect {
                x: area.x + 2,
                y: area.y,
                width: area.width - 4,
                height: area.height,
            };

            let block = Block::default().borders(Borders::ALL).title(" Details ");
            let block_inner = block.inner(block_area);
            frame.render_widget(block, block_area);

            let block_layout = Layout::default()
                .direction(Direction::Vertical)
                .constraints(vec![Constraint::Length(3), Constraint::Min(0)])
                .split(block_inner);

            let top_layout = Layout::default()
                .direction(Direction::Horizontal)
                .constraints(vec![Constraint::Length(50), Constraint::Length(50)])
                .split(block_layout[0]);

            let left_side = Paragraph::new(vec![
                Line::from(vec![
                    Span::from("WPS Status: "),
                    Span::from(
                        ap.wps_data
                            .as_ref()
                            .map_or("Not Present".to_string(), |f| f.setup_state.to_string()),
                    ),
                ]),
                Line::from(vec![
                    Span::from("OUI Lookup: "),
                    Span::from(
                        ap.oui_data
                            .as_ref()
                            .map_or("Unknown".to_string(), |f| f.long_name()),
                    ),
                ]),
                Line::from(vec![
                    Span::from("WPA Mode: "),
                    Span::from(ap.information.get_rsn_akm_true()),
                ]),
            ]);

            let right_side = Paragraph::new(vec![
                Line::from(vec![
                    Span::from("Make: "),
                    Span::from(ap.wps_data.as_ref().map_or("Unknown".to_string(), |f| {
                        let str = f.manufacturer.to_string();
                        if str.is_empty() {
                            "Unknown".to_string()
                        } else {
                            str
                        }
                    })),
                ]),
                Line::from(vec![
                    Span::from("Device Name: "),
                    Span::from(ap.wps_data.as_ref().map_or("Unknown".to_string(), |f| {
                        let str = f.device_name.to_string();
                        if str.is_empty() {
                            "Unknown".to_string()
                        } else {
                            str
                        }
                    })),
                ]),
                Line::from(vec![
                    Span::from("Device Type: "),
                    Span::from(ap.wps_data.as_ref().map_or("Unknown".to_string(), |f| {
                        let str = f.primary_device_type.to_string();
                        if str.is_empty() {
                            "Unknown".to_string()
                        } else {
                            str
                        }
                    })),
                ]),
            ]);

            frame.render_widget(left_side, top_layout[0]);
            frame.render_widget(right_side, top_layout[1]);

            if ap.client_list.size() > 0 {
                // Draw header
                let mut current_y = 0;
                let row_layout = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints(vec![
                        Constraint::Min(20),
                        Constraint::Min(10),
                        Constraint::Min(10),
                        Constraint::Min(10),
                    ])
                    .split(Rect {
                        x: block_layout[1].x,
                        y: block_layout[1].y + current_y,
                        width: block_layout[1].width,
                        height: 1,
                    });
                let cl = Paragraph::new("Clients");
                let last = Paragraph::new("Last");
                let rssi = Paragraph::new("RSSI");
                let tx = Paragraph::new("Tx");
                frame.render_widget(cl, row_layout[0]);
                frame.render_widget(last, row_layout[1]);
                frame.render_widget(rssi, row_layout[2]);
                frame.render_widget(tx, row_layout[3]);

                // Draw clients
                for (idx, client) in ap.client_list.clone().get_devices().values().enumerate() {
                    let last = idx == ap.client_list.size() - 1;
                    let icon = if last { "└ " } else { "├ " };

                    current_y += 1;
                    let row_layout = Layout::default()
                        .direction(Direction::Horizontal)
                        .constraints(vec![
                            Constraint::Min(20),
                            Constraint::Min(10),
                            Constraint::Min(10),
                            Constraint::Min(10),
                        ])
                        .split(Rect {
                            x: block_layout[1].x,
                            y: block_layout[1].y + current_y,
                            width: block_layout[1].width,
                            height: 1,
                        });
                    let cl = Paragraph::new(format!(" {}{}", icon, client.mac_address));
                    let last = Paragraph::new(epoch_to_string(client.last_recv));
                    let rssi = Paragraph::new(match client.last_signal_strength.value {
                        0 => "".to_string(),
                        _ => client.last_signal_strength.value.to_string(),
                    });
                    let tx = Paragraph::new(format!("{}", client.interactions));
                    frame.render_widget(cl, row_layout[0]);
                    frame.render_widget(last, row_layout[1]);
                    frame.render_widget(rssi, row_layout[2]);
                    frame.render_widget(tx, row_layout[3]);
                }
            }

            /*


            let make_model_block =
                Paragraph::new(ap.wps_data.as_ref().map_or("Unknown".to_string(), |f| {
                    let str = format!("{} {}", f.manufacturer, f.device_name);
                    if str.is_empty() {
                        "Unknown".to_string()
                    } else {
                        str
                    }
                }))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Make / Model "),
                );

            frame.render_widget(wps_block, selected_layout[0]);
            frame.render_widget(oui_block, selected_layout[1]);
            frame.render_widget(make_model_block, selected_layout[2]);
            */
        }
    }
}

fn create_sta_page(oxide: &mut OxideRuntime, frame: &mut Frame<'_>, area: Rect) {
    // Update the table data (from the real source) - This allows us to "pause the data"
    if !oxide.ui_state.paused {
        oxide.ui_state.sta_table_data = oxide.unassoc_clients.clone();
    }

    let (mut headers, rows) = oxide.ui_state.sta_table_data.get_table(
        oxide.ui_state.sta_state.selected(),
        oxide.ui_state.sta_sort,
        oxide.ui_state.sta_sort_reverse,
    );

    let selected_object = if let Some(sel_idx) = oxide.ui_state.sta_state.selected() {
        oxide
            .ui_state
            .sta_table_data
            .get_devices_sorted()
            .get(sel_idx)
    } else {
        None
    };

    oxide.ui_state.sta_selected_item = selected_object.cloned();

    if oxide.ui_state.copy_short {
        if let Some(station) = selected_object {
            set_clipboard_content(station.mac_address.to_string().to_string()).unwrap();
        }
        oxide.ui_state.copy_short = false;
    }
    if oxide.ui_state.copy_long {
        if let Some(station) = selected_object {
            set_clipboard_content(station.to_json_str().to_string()).unwrap();
        }
        oxide.ui_state.copy_long = false;
    }

    // Fill Rows
    let mut rows_vec: Vec<Row> = vec![];
    for (mut row, height) in rows {
        if oxide.ui_state.paused {
            row[3] = "Paused".to_owned();
        }
        rows_vec.push(Row::new(row).height(height));
    }

    // Set headers for sort
    let sort_icon = if oxide.ui_state.sta_sort_reverse {
        "▲"
    } else {
        "▼"
    };
    match oxide.ui_state.sta_sort {
        0 => headers[2] = format!("{} {}", headers[2], sort_icon),
        1 => headers[1] = format!("{} {}", headers[1], sort_icon),
        2 => headers[3] = format!("{} {}", headers[3], sort_icon),
        3 => headers[4] = format!("{} {}", headers[4], sort_icon),
        4 => headers[5] = format!("{} {}", headers[5], sort_icon),
        _ => headers[2] = format!("{} {}", headers[2], sort_icon),
    };

    let selected_style = Style::default().add_modifier(Modifier::REVERSED);

    let table: Table<'_> = Table::new(
        rows_vec.clone(),
        vec![
            Constraint::Min(30),    // Mac
            Constraint::Length(10), // RSSI
            Constraint::Length(10), // Last
            Constraint::Length(10), // Tx
            Constraint::Length(10), // M2
            Constraint::Length(20), // Probes
        ],
    )
    .segment_size(SegmentSize::EvenDistribution)
    .highlight_style(selected_style)
    .highlight_symbol(">> ")
    .highlight_spacing(HighlightSpacing::Always)
    .header(Row::new(headers).style(Style::new().bold()))
    .block(Block::default().borders(Borders::RIGHT));

    let scrollbar = Scrollbar::default()
        .orientation(ScrollbarOrientation::VerticalRight)
        .begin_symbol(Some("↑"))
        .end_symbol(Some("↓"));

    let mut scrollbar_state = ScrollbarState::new(oxide.get_current_menu_len())
        .position(oxide.ui_state.sta_state.selected().unwrap_or(0));

    frame.render_stateful_widget(table, area, &mut oxide.ui_state.sta_state);
    frame.render_stateful_widget(
        scrollbar,
        area.inner(&Margin {
            vertical: 0,
            horizontal: 0,
        }),
        &mut scrollbar_state,
    );
}

fn create_hs_page(oxide: &mut OxideRuntime, frame: &mut Frame<'_>, area: Rect) {
    // Update the table data (from the real source) - This allows us to "pause the data"
    if !oxide.ui_state.paused {
        oxide.ui_state.hs_table_data = oxide.handshake_storage.clone();
    }

    let (headers, rows) = oxide.ui_state.hs_table_data.get_table(
        oxide.ui_state.hs_state.selected(),
        oxide.ui_state.copy_short,
        oxide.ui_state.copy_long,
    );

    let selected_object = if let Some(sel_idx) = oxide.ui_state.hs_state.selected() {
        oxide.ui_state.hs_table_data.get_sorted().get(sel_idx)
    } else {
        None
    };

    oxide.ui_state.hs_selected_item = selected_object.cloned();

    if oxide.ui_state.copy_short {
        if let Some(hs) = selected_object {
            set_clipboard_content(hs.json_summary().to_string()).unwrap();
        }
        oxide.ui_state.copy_short = false;
    }
    if oxide.ui_state.copy_long {
        if let Some(hs) = selected_object {
            set_clipboard_content(hs.json_detail().to_string()).unwrap();
        }
        oxide.ui_state.copy_long = false;
    }

    // Fill Rows
    let mut rows_vec: Vec<Row> = vec![];
    for (row, height) in rows {
        rows_vec.push(Row::new(row).height(height));
    }

    /*
    Timestamp
    AP MAC
    Client MAC
    SSID
    M1
    M2
    M3
    M4
    PM
    OK
    NC
    */

    let selected_style = Style::default().add_modifier(Modifier::REVERSED);

    let table: Table<'_> = Table::new(
        rows_vec.clone(),
        vec![
            Constraint::Min(15),   // Timestamp
            Constraint::Min(16),   // AP MAC
            Constraint::Min(16),   // Client MAC
            Constraint::Min(20),   // SSID
            Constraint::Length(2), // M1
            Constraint::Length(2), // M2
            Constraint::Length(2), // M3
            Constraint::Length(3), // M4
            Constraint::Length(3), // PM
            Constraint::Length(3), // OK
            Constraint::Min(3),    // NC
        ],
    )
    .segment_size(SegmentSize::EvenDistribution)
    .highlight_style(selected_style)
    .header(Row::new(headers).style(Style::new().bold()))
    .highlight_symbol(">> ")
    .highlight_spacing(HighlightSpacing::Always)
    .block(Block::default().borders(Borders::RIGHT));

    let scrollbar = Scrollbar::default()
        .orientation(ScrollbarOrientation::VerticalRight)
        .begin_symbol(Some("↑"))
        .end_symbol(Some("↓"));

    let mut scrollbar_state = ScrollbarState::new(oxide.get_current_menu_len())
        .position(oxide.ui_state.hs_state.selected().unwrap_or(0));

    frame.render_stateful_widget(table, area, &mut oxide.ui_state.hs_state);
    frame.render_stateful_widget(
        scrollbar,
        area.inner(&Margin {
            vertical: 0,
            horizontal: 0,
        }),
        &mut scrollbar_state,
    );
}

fn create_status_page(oxide: &mut OxideRuntime, frame: &mut Frame<'_>, area: Rect) {
    let status_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(vec![Constraint::Length(9), Constraint::Percentage(75)])
        .split(area);

    let top_area = status_layout[0];
    let bottom_area = status_layout[1];

    // Splits top area in half
    let top_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(vec![Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(top_area);

    let top_left_block = Block::default()
        .borders(Borders::ALL)
        .title(" Stats for nerds ")
        .padding(Padding::uniform(1));

    /*
    self.lat = new_data.lat.or(self.lat);
    self.lon = new_data.lon.or(self.lon);
    self.alt = new_data.alt.or(self.alt);
    self.alt_g = new_data.alt_g.or(self.alt_g);
    self.eph = new_data.eph.or(self.eph);
    self.epv = new_data.epv.or(self.epv);
    self.speed = new_data.speed.or(self.speed);
    self.heading = new_data.heading.or(self.heading);
    self.fix = new_data.fix.or(self.fix);
    self.hdop = new_data.hdop.or(self.hdop);
    self.vdop = new_data.vdop.or(self.vdop);
    self.timestamp = new_data.timestamp.or(self.timestamp.clone());
    */

    let gpsdata = oxide.file_data.gps_source.get_gps();
    if gpsdata.has_gpsd() {
        let top_right_block = Block::default()
            .borders(Borders::ALL)
            .title(" GPS Data ")
            .padding(Padding::uniform(1));

        // Splits Top Right Block in half
        let top_right_layout: std::rc::Rc<[Rect]> = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(vec![Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(top_right_block.inner(top_layout[1]));

        frame.render_widget(top_right_block, top_layout[1]);
        let mut gps_text_one: Vec<Line<'_>> = vec![];
        let mut gps_text_two: Vec<Line<'_>> = vec![];

        if let Some(fix) = gpsdata.fix {
            let fix_str = match fix {
                1 => Span::styled("2D Fix", Style::new().light_magenta()),
                2 => Span::styled("3D Fix", Style::new().green()),
                _ => Span::styled("No Fix", Style::new().red()), // If the u8 value doesn't correspond to a Mode
            };
            gps_text_one.push(Line::from(vec![Span::from("Fix: "), fix_str]));
        } else {
            gps_text_one.push(Line::from("Fix: ?".to_string()));
        }
        if let Some(lat) = gpsdata.lat {
            gps_text_one.push(Line::from(format!("Latitude: {}°", lat)));
        } else {
            gps_text_one.push(Line::from("Latitude: ?".to_string()));
        }
        if let Some(lon) = gpsdata.lon {
            gps_text_one.push(Line::from(format!("Longitude: {}°", lon)));
        } else {
            gps_text_one.push(Line::from("Longitude: ?".to_string()));
        }
        if let Some(alt) = gpsdata.alt {
            gps_text_one.push(Line::from(format!("Alt (MSL): {}m", alt)));
        } else {
            gps_text_one.push(Line::from("Alt (MSL): ?".to_string()));
        }
        if let Some(alt) = gpsdata.alt_g {
            gps_text_one.push(Line::from(format!("Alt (AGL): {}m", alt)));
        } else {
            gps_text_one.push(Line::from("Alt (AGL): ?".to_string()));
        }

        if let Some(speed) = gpsdata.speed {
            gps_text_two.push(Line::from(format!("Speed: {}m/s", speed)));
        } else {
            gps_text_two.push(Line::from("Speed: ?".to_string()));
        }
        if let Some(heading) = gpsdata.heading {
            gps_text_two.push(Line::from(format!("Heading: {}°", heading)));
        } else {
            gps_text_two.push(Line::from("Heading: ?".to_string()));
        }

        if let Some(eph) = gpsdata.eph {
            gps_text_two.push(Line::from(format!("EPH: {}m", eph)));
        } else {
            gps_text_two.push(Line::from("EPH: ?".to_string()));
        }
        if let Some(epv) = gpsdata.epv {
            gps_text_two.push(Line::from(format!("EPV: {}m", epv)));
        } else {
            gps_text_two.push(Line::from("EPV: ?".to_string()));
        }
        if let Some(time) = gpsdata.timestamp {
            gps_text_two.push(Line::from(format!("Time: {}", time)));
        } else {
            gps_text_two.push(Line::from("Time: ?".to_string()));
        }

        let para_one = Paragraph::new(gps_text_one).alignment(Alignment::Left);
        let para_two = Paragraph::new(gps_text_two).alignment(Alignment::Left);

        frame.render_widget(para_one, top_right_layout[0]);
        frame.render_widget(para_two, top_right_layout[1]);
    } else {
        let title = if oxide.ui_state.ui_snowstorm {
            " Snowfall for geeks (No GPS) "
        } else {
            " Matrix for geeks (No GPS) "
        };

        let top_right_block = Block::default().borders(Borders::ALL).title(title);

        if oxide.ui_state.ui_snowstorm {
            let snowstorm = Snowstorm::frame(
                oxide.ui_state.snowstorm.clone(),
                top_right_block.inner(top_layout[1]),
            );
            oxide.ui_state.snowstorm = snowstorm.clone();
            frame.render_widget(snowstorm, top_right_block.inner(top_layout[1]));
        } else {
            let matrix_snowstorm = MatrixSnowstorm::frame(
                oxide.ui_state.matrix_snowstorm.clone(),
                top_right_block.inner(top_layout[1]),
            );
            oxide.ui_state.matrix_snowstorm = matrix_snowstorm.clone();
            frame.render_widget(matrix_snowstorm, top_right_block.inner(top_layout[1]));
        }

        frame.render_widget(top_right_block, top_layout[1]);
    }

    // Splits Top Left Block in half
    let top_left_layout: std::rc::Rc<[Rect]> = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(vec![Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(top_left_block.inner(top_layout[0]));

    frame.render_widget(top_left_block, top_layout[0]);

    let mut status_text_one: Vec<Line<'_>> = vec![];
    status_text_one.push(Line::from(format!("Beacons: {}", oxide.counters.beacons)));
    status_text_one.push(Line::from(format!(
        "Probe Requests: {}",
        oxide.counters.probe_requests
    )));
    status_text_one.push(Line::from(format!(
        "Probe Responses: {}",
        oxide.counters.probe_responses
    )));
    status_text_one.push(Line::from(format!(
        "Authentications: {}",
        oxide.counters.authentication
    )));
    status_text_one.push(Line::from(format!(
        "Associations: {}",
        oxide.counters.association
    )));

    let mut status_text_two = vec![];
    status_text_two.push(Line::from(format!(
        "Deauthentications: {}",
        oxide.counters.deauthentication
    )));
    status_text_two.push(Line::from(format!(
        "Reassociations: {}",
        oxide.counters.reassociation
    )));
    status_text_two.push(Line::from(format!(
        "Control Frames: {}",
        oxide.counters.control_frames
    )));
    status_text_two.push(Line::from(format!("Data: {}", oxide.counters.data)));

    status_text_two.push(Line::from(format!(
        "Null Data: {}",
        oxide.counters.null_data
    )));

    let para_one = Paragraph::new(status_text_one).alignment(Alignment::Left);
    let para_two = Paragraph::new(status_text_two).alignment(Alignment::Left);

    frame.render_widget(para_one, top_left_layout[0]);
    frame.render_widget(para_two, top_left_layout[1]);

    // Handle the Messages Window
    // Update the table data (from the real source) - This allows us to "pause the data"
    if !oxide.ui_state.paused {
        oxide.ui_state.messages_table_data = oxide.status_log.get_all_messages();
        oxide.ui_state.messages_table_data.reverse();
    }

    let selected_style = Style::default().add_modifier(Modifier::REVERSED);
    let headers = vec![
        Cell::from("Timestamp".to_string()),
        Cell::from("Type".to_string()),
        Cell::from("Content".to_string()),
    ];

    // Fill Rows
    let mut rows_vec: Vec<Row> = vec![];
    for status in &oxide.ui_state.messages_table_data {
        let time_cell = Cell::from(format!(
            "{}",
            status.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        let type_cell = match status.message_type {
            crate::status::MessageType::Error => {
                Cell::from(status.message_type.to_string()).style(Style::new().fg(Color::Red))
            }
            crate::status::MessageType::Warning => {
                Cell::from(status.message_type.to_string()).style(Style::new().fg(Color::Yellow))
            }
            crate::status::MessageType::Priority => {
                Cell::from(status.message_type.to_string()).style(Style::new().fg(Color::Green))
            }
            crate::status::MessageType::Info => Cell::from(status.message_type.to_string()),
            crate::status::MessageType::Status => {
                Cell::from(status.message_type.to_string()).style(Style::new().fg(Color::Cyan))
            }
        };

        rows_vec.push(Row::new(vec![
            time_cell,
            type_cell,
            Cell::from(status.content.to_string()),
        ]));
    }

    let table: Table<'_> = Table::new(
        rows_vec,
        vec![
            Constraint::Length(20), // Timestamp
            Constraint::Length(10), // Type
            Constraint::Min(50),    // Message
        ],
    )
    .segment_size(SegmentSize::EvenDistribution)
    .highlight_style(selected_style)
    .highlight_spacing(HighlightSpacing::Never)
    .header(Row::new(headers).bold())
    .block(Block::default().borders(Borders::ALL).title(" Messages "));

    let scrollbar = Scrollbar::default()
        .orientation(ScrollbarOrientation::VerticalRight)
        .begin_symbol(Some("↑"))
        .end_symbol(Some("↓"));

    let mut scrollbar_state = ScrollbarState::new(oxide.status_log.size())
        .position(oxide.ui_state.messages_state.selected().unwrap_or(0));

    frame.render_stateful_widget(table, bottom_area, &mut oxide.ui_state.messages_state);
    frame.render_stateful_widget(
        scrollbar,
        bottom_area.inner(&Margin {
            vertical: 1,
            horizontal: 0,
        }),
        &mut scrollbar_state,
    );
}

#[derive(Debug, Default, Setters)]
struct Popup<'a> {
    #[setters(into)]
    title: Line<'a>,
    #[setters(into)]
    content: Text<'a>,
    border_style: Style,
    title_style: Style,
    style: Style,
}

impl Widget for Popup<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // ensure that all cells under the popup are cleared to avoid leaking content
        Clear.render(area, buf);
        let block = Block::new()
            .title(self.title)
            .title_style(self.title_style)
            .borders(Borders::ALL)
            .border_style(self.border_style);
        Paragraph::new(self.content)
            .wrap(Wrap { trim: true })
            .style(self.style)
            .block(block)
            .alignment(Alignment::Center)
            .render(area, buf);
    }
}
