use derive_setters::Setters;
use gpsd_proto::Mode;
use libwifi::frame::components::MacAddress;
use std::{io::Result, time::Instant};

use crate::{
    snowstorm::Snowstorm,
    tabbedblock::{
        tab::{Position, Tab},
        tabbedblock::TabbedBlock,
        tabbedblock::{BorderType, TabType},
    },
    MenuType, OxideRuntime,
};

use nl80211_ng::get_interface_info_idx;

// Ratatui imports:

use ratatui::{
    buffer::Buffer,
    layout::{Alignment, Constraint, Direction, Layout, Margin, Rect, SegmentSize},
    prelude::{CrosstermBackend, Stylize, Terminal},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        Block, Borders, Cell, Clear, HighlightSpacing, Padding, Paragraph, Row, Scrollbar,
        ScrollbarOrientation, ScrollbarState, Table, Widget, Wrap,
    },
    Frame,
};

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
                Span::raw(" | sort table: ").style(Style::new()),
                Span::styled("[e]", Style::default().reversed()),
                Span::raw(" | reverse: ").style(Style::new()),
                Span::styled("[r]", Style::default().reversed()),
                Span::raw(" | change tab: ").style(Style::new()),
                Span::styled("[a]/[d]", Style::default().reversed()),
                Span::raw(" | pause: ").style(Style::new()),
                Span::styled("[space]", Style::default().reversed()),
                Span::raw(" | scroll: ").style(Style::new()),
                Span::styled("[w/W]/[s/S]", Style::default().reversed()),
                Span::raw(" |").style(Style::new()),
            ]))
            .alignment(Alignment::Center),
            full_layout[2],
        );
    })?;
    Ok(())
}

fn create_status_bar(
    frame: &mut Frame<'_>,
    top_area: Rect,
    oxide: &mut OxideRuntime,
    start_time: Instant,
    framerate: u64,
) {
    oxide.interface = get_interface_info_idx(oxide.interface.index.unwrap()).unwrap();
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
                Span::from("█▀█ █▀█ █▀▀ █▀▄ █ █").style(Style::new().fg(Color::Red)),
                Span::from(" █▀█ █ █ ▀█▀ █▀▄ █▀▀").style(Style::new().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::from("█▀█ █ █ █ █ █▀▄  █ ").style(Style::new().fg(Color::Red)),
                Span::from(" █ █ ▄▀▄  █  █ █ █▀▀").style(Style::new().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::from("▀ ▀ ▀ ▀ ▀▀▀ ▀ ▀  ▀ ").style(Style::new().fg(Color::Red)),
                Span::from(" ▀▀▀ ▀ ▀ ▀▀▀ ▀▀  ▀▀▀").style(Style::new().fg(Color::White)),
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
        oxide.frame_count, framerate
    ));

    let flow = match oxide.ui_state.paused {
        true => Span::from("Paused").fg(Color::Red),
        false => Span::from("Running"),
    };

    let dataflow = Line::from(vec![Span::from("Data: "), flow]);

    let status_text = vec![time_str, frame_count, dataflow];

    frame.render_widget(
        Paragraph::new(status_text).alignment(Alignment::Right),
        right_side_layout[1],
    );

    let interface_name = String::from_utf8(
        oxide
            .interface
            .name
            .clone()
            .expect("Cannot get interface name"),
    );

    let mac_addr =
        MacAddress::from_vec(oxide.interface.mac.clone().expect("Cannot get mac address"));

    // Top Left
    let interface = format!(
        "Interface: {}",
        interface_name.expect("Cannot get interface name")
    );
    let mac: String = format!("MacAddr: {}", mac_addr.expect("Cannot get mac address"));
    let channel = format!(
        "Frequency: {}",
        oxide
            .interface
            .frequency
            .clone()
            .unwrap_or_default()
            .print()
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

    // Fill Rows
    let mut rows_vec: Vec<Row> = vec![];
    for (mut row, height) in rows {
        if oxide.ui_state.paused {
            row[3] = "Paused".to_owned();
        }
        rows_vec.push(Row::new(row).height(height));
    }

    // Set headers for sort
    let sort_icon = if oxide.ui_state.ap_sort_reverse {
        "▲"
    } else {
        "▼"
    };
    match oxide.ui_state.ap_sort {
        0 => headers[3] = format!("{} {}", headers[3], sort_icon),
        1 => headers[2] = format!("{} {}", headers[2], sort_icon),
        2 => headers[1] = format!("{} {}", headers[1], sort_icon),
        3 => headers[5] = format!("{} {}", headers[5], sort_icon),
        4 => headers[6] = format!("{} {}", headers[6], sort_icon),
        5 => headers[8] = format!("{} {}", headers[8], sort_icon),
        6 => headers[9] = format!("{} {}", headers[9], sort_icon),
        _ => headers[3] = format!("{} {}", headers[3], sort_icon),
    };

    let selected_style = Style::default().add_modifier(Modifier::REVERSED);

    let table: Table<'_> = Table::new(
        rows_vec.clone(),
        vec![
            Constraint::Min(16),   // Mac
            Constraint::Min(4),    // CH
            Constraint::Min(6),    // RSSI
            Constraint::Min(6),    // Last
            Constraint::Min(25),   // SSID
            Constraint::Min(9),    // Clients
            Constraint::Length(5), // Tx
            Constraint::Length(5), // MFP
            Constraint::Min(6),    // 4wHS
            Constraint::Min(7),    // PMKID
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
}

fn create_sta_page(oxide: &mut OxideRuntime, frame: &mut Frame<'_>, area: Rect) {
    // Update the table data (from the real source) - This allows us to "pause the data"
    if !oxide.ui_state.paused {
        oxide.ui_state.cl_table_data = oxide.unassoc_clients.clone();
    }

    let (mut headers, rows) = oxide.ui_state.cl_table_data.get_table(
        oxide.ui_state.cl_state.selected(),
        oxide.ui_state.cl_sort,
        oxide.ui_state.cl_sort_reverse,
    );

    // Fill Rows
    let mut rows_vec: Vec<Row> = vec![];
    for (mut row, height) in rows {
        if oxide.ui_state.paused {
            row[2] = "Paused".to_owned();
        }
        rows_vec.push(Row::new(row).height(height));
    }

    // Set headers for sort
    let sort_icon = if oxide.ui_state.cl_sort_reverse {
        "▲"
    } else {
        "▼"
    };
    match oxide.ui_state.cl_sort {
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
        .position(oxide.ui_state.cl_state.selected().unwrap_or(0));

    frame.render_stateful_widget(table, area, &mut oxide.ui_state.cl_state);
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

    let (headers, rows) = oxide
        .ui_state
        .hs_table_data
        .get_table(oxide.ui_state.hs_state.selected());

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

    let gpsdata = oxide.gps_source.get_gps();
    if gpsdata.has_fix() {
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
        let top_right_block = Block::default()
            .borders(Borders::ALL)
            .title(" Snowfall for geeks (No GPS) ");

        let snowstorm = Snowstorm::frame(
            oxide.ui_state.snowstorm.clone(),
            top_right_block.inner(top_layout[1]),
        );
        oxide.ui_state.snowstorm = snowstorm.clone();

        frame.render_widget(snowstorm, top_right_block.inner(top_layout[1]));
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
            crate::status::MessageType::Info => Cell::from(status.message_type.to_string()),
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
            .render(area, buf);
    }
}
