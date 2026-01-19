use iced::{
    Length, Alignment, Element, Subscription, Theme, Task, Font, font, padding, time,
    widget::{button, column, container, row, scrollable, space, table, text, text_input},
};
use iced::widget;
use iced::keyboard;
use iced::event;
use iced::time::{Duration, Instant};

use widgets::generic_overlay::{self, *};
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, SocketInfo, error::Error};
use sysinfo::{ProcessesToUpdate, RefreshKind, System};

mod icon;

#[derive(Debug, Clone)]
pub enum Message {
    Settings,
    RefreshData,
    FilterChanged(String),
    FilterChangedImmediate(String),
    CheckDebounce,
    SelectAutocomplete(String),
    AutocompleteNavigate(AutocompleteNav),
}
struct App {
    process_info: DataState<Vec<SocketDisplay>, Error>,
    system_info: System,
    filter_text: String,
    filter_text_staged: String,
    last_keystroke: Option<Instant>,
    debounce_duration: std::time::Duration,
    autocomplete_suggestions: Vec<AutocompleteOption>,
    autocomplete_selected_index: Option<usize>,
    text_input_id: widget::Id,
}

enum DataState<T, E> {
    NotLoaded,
    Loading,
    Loaded(Result<T, E>),
}

#[derive(Clone)]
struct SocketDisplay {
    protocol: String,
    state: String,
    local_addr: String,
    remote_addr: String,
    pid: String,
    process_name: String,
}

impl SocketDisplay {
    fn from_socket(socket: &SocketInfo, sys: &System) -> Self {
        let protocol = match socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(_) => "TCP".to_string(),
            ProtocolSocketInfo::Udp(_) => "UDP".to_string(),
        };

        let (local_addr, remote_addr, state) = match &socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp_info) => (
                format!("{}:{}", tcp_info.local_addr, tcp_info.local_port),
                format!("{}:{}", tcp_info.remote_addr, tcp_info.remote_port),
                format!("{:?}", tcp_info.state),
            ),
            ProtocolSocketInfo::Udp(udp_info) => (
                format!("{}:{}", udp_info.local_addr, udp_info.local_port),
                String::from("*:*"),
                String::from("-"),
            ),
        };

        let process_name = socket
            .associated_pids
            .first()
            .and_then(|&pid| sys.process(sysinfo::Pid::from_u32(pid)))
            .map(|process| process.name().to_string_lossy().to_string())
            .unwrap_or_else(|| String::from("Unknown"));

        let pid = socket
            .associated_pids
            .first()
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| String::from("-"));

        Self {
            protocol,
            state,
            local_addr,
            remote_addr,
            pid,
            process_name,
        }
    }
}

impl App {
    pub fn new() -> (Self, Task<Message>) {
        let sys = System::new_with_specifics(
            RefreshKind::everything(),
        );        
        (
            Self {
                process_info: DataState::NotLoaded,
                system_info: sys,
                filter_text: String::new(),
                filter_text_staged: String::new(),
                last_keystroke: None,
                debounce_duration: std::time::Duration::from_millis(250),
                autocomplete_suggestions: Vec::new(),
                autocomplete_selected_index: None,
                text_input_id: widget::Id::unique(),
            },
            Task::done(Message::RefreshData)
        )
    }

    fn title(&self) -> String {
        String::from("Easy Net Stat")
    }

    fn theme(&self) -> Theme {
        Theme::Nord
    }

    pub fn window_settings() -> iced::window::Settings {
        iced::window::Settings {
            size: iced::Size::new(1275.0, 768.0),
            min_size: Some( iced::Size::new(1275.0, 768.0) ),
            ..iced::window::Settings::default()
        }
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Settings => {
                // toggle Settings
            }
            Message::FilterChangedImmediate(value) => {
                self.filter_text = self.filter_text_staged.clone();
            }
            Message::RefreshData => {
                let socket_info = get_netstat(&mut self.system_info);
                
                self.process_info = DataState::Loaded(
                    socket_info.map(|sockets| {
                        sockets
                            .iter()
                            .map(|socket| SocketDisplay::from_socket(socket, &self.system_info))
                            .collect()
                    })
                );
            }
            Message::FilterChanged(value) => {
                self.filter_text_staged = value;
                self.last_keystroke = Some(Instant::now());
                self.autocomplete_suggestions = self.generate_autocomplete();

                // Reset selected index when typing
                self.autocomplete_selected_index = if self.autocomplete_suggestions.is_empty() {
                    None
                } else {
                    Some(0)
                };
            }
            Message::CheckDebounce => {
                if let Some(last) = self.last_keystroke {
                    if last.elapsed() >= self.debounce_duration {
                        self.filter_text = self.filter_text_staged.clone();
                    }
                }
            }
            Message::SelectAutocomplete(value) => {
                // Replace last token with selected value
                let mut tokens: Vec<&str> = self.filter_text_staged.split_whitespace().collect();
                if !tokens.is_empty() {
                    tokens.pop();
                }
                tokens.push(&value);

                // Only add trailing space if the value doesn't end with ':'
                let trailing_space = if value.ends_with(':') {
                    ""
                } else {
                    " "
                };

                self.filter_text_staged = tokens.join(" ") + trailing_space;

                // Clear autocomplete
                self.autocomplete_suggestions.clear();
                self.autocomplete_selected_index = None;
                
                if value.ends_with(':') {
                    self.autocomplete_suggestions = self.generate_autocomplete();
                }

                self.last_keystroke = Some(Instant::now());
                return iced::widget::operation::focus(self.text_input_id.clone())
            }
            Message::AutocompleteNavigate(nav) => {
                match nav {
                    AutocompleteNav::Down => {
                        if let Some(current) = self.autocomplete_selected_index {
                            self.autocomplete_selected_index = Some(
                                (current + 1).min(self.autocomplete_suggestions.len().saturating_sub(1))
                            );
                        } else if !self.autocomplete_suggestions.is_empty() {
                            self.autocomplete_selected_index = Some(0);
                        }
                    }
                    AutocompleteNav::Up => {
                        if let Some(current) = self.autocomplete_selected_index {
                            self.autocomplete_selected_index = Some(current.saturating_sub(1));
                        }
                    }
                    AutocompleteNav::Select => {
                        if let Some(index) = self.autocomplete_selected_index {
                            if let Some(option) = self.autocomplete_suggestions.get(index) {
                                return self.update(Message::SelectAutocomplete(option.insert.clone()));
                            }
                        }
                    }
                    AutocompleteNav::Escape => {
                        self.autocomplete_suggestions.clear();
                        self.autocomplete_selected_index = None;
                    }
                }
            }
        }
        Task::none()
    }

    pub fn view<'a>(&'a self) -> Element<'a, Message> {
        let process: Element<Message> = match &self.process_info {
            DataState::Loaded(Ok(sockets)) => {
                let filtered: Vec<_> = sockets.iter()
                    .filter(|socket| {
                        if self.filter_text.is_empty() {
                            return true;
                        }

                        let expr = parse_filter(&self.filter_text);
                        let optimized = optimize_filter(expr);
                        optimized.matches(socket)
                    })
                    .collect();
                
                    let bold = |header| {
                        text(header).font(Font {
                            weight: font::Weight::Bold,
                            ..Font::DEFAULT
                        })
                    };

                    let columns = [
                        table::column(bold("Protocol"), |socket: &SocketDisplay| text(&socket.protocol)),
                        table::column(bold("State"), |socket: &SocketDisplay| text(&socket.state)),
                        table::column(bold("Local Address"), |socket: &SocketDisplay| text(&socket.local_addr)),
                        table::column(bold("Remote Address"), |socket: &SocketDisplay| text(&socket.remote_addr)),
                        table::column(bold("PID"), |socket: &SocketDisplay| text(&socket.pid))
                            .align_x(Alignment::End)
                            .align_y(Alignment::Center),
                        table::column(bold("Process"), |socket: &SocketDisplay| text(&socket.process_name)),
                    ];

                    scrollable(
                        container(
                            table(columns, filtered)
                                .padding_x(10.0)
                                .padding_y(5.0)
                        ).padding(padding::right(15.0))
                    ).into()
            }
            DataState::Loading => text("Loading...").into(),
            DataState::NotLoaded => button("Load Network Info").into(),
            DataState::Loaded(Err(e)) => text(format!("Error: {}", e)).into(),
        };

        container(
            column![
                row![
                    space::horizontal(),
                    text("Net Stat")
                        .size(26),
                    space::horizontal(),
                    button(icon::settings())
                        .style(button::text)
                        .on_press(Message::Settings)
                ]
                .spacing(10)
                .align_y(Alignment::Center)
                .width(Length::Fill)
                .padding(10.0),
                row![
                    text("Filter : "),
                    overlay_button(
                        text_input("Filter text i.e. port:5013", &self.filter_text_staged)
                            .on_input(Message::FilterChanged)
                            .on_submit(Message::FilterChangedImmediate(self.filter_text_staged.clone()))
                            .on_paste(Message::FilterChangedImmediate)
                            .id(self.text_input_id.clone())
                            .size(16)
                            .padding(5.0),
                        "",
                        column(
                            self.autocomplete_suggestions.iter().enumerate().map(|(idx, suggestion)| {
                                let is_selected = self.autocomplete_selected_index == Some(idx);
                                
                                button(text(&suggestion.display))
                                    .on_press(Message::SelectAutocomplete(suggestion.insert.clone()))
                                    .width(Length::Fill)
                                    .style(if is_selected {
                                        button::primary
                                    } else {
                                        button::secondary
                                    })
                                    .into()
                            })
                        )
                        .spacing(2)
                    )
                    .is_open(!self.autocomplete_suggestions.is_empty())
                    .on_hover()
                    .hover_position(Position::Bottom)
                    .hover_alignment(Alignment::Start)
                    .style(button::text)
                    .hover_gap(0.0)
                    .overlay_style(generic_overlay::blank)
                    .padding(0.0)
                    .overlay_padding(0.0)
                    .hide_header()
                    .interactive_base(true),

                    button(icon::refresh())
                        .on_press(Message::RefreshData)
                        .style(button::text)
                ]
                .spacing(10)
                .align_y(Alignment::Center)
                .padding(10.0),
                container(
                    column![
//                        auto_complete,
                        process
                    ]
                )
            ]
            .width(Length::Fill)
            .padding(10.0)
        ).into()
    }

    fn subscription(&self) -> Subscription<Message> {
        use iced::keyboard::{key, Key};

        let tick = time::every(std::time::Duration::from_millis(100)).map(|_| Message::CheckDebounce);

        let keyboard = event::listen_with(|event, _, _| 
            match event {
                event::Event::Keyboard(keyboard::Event::KeyPressed { key, .. }) => {
                    match key {
                        Key::Named(key::Named::ArrowDown) => {
                            Some(Message::AutocompleteNavigate(AutocompleteNav::Down))
                        }
                        Key::Named(key::Named::ArrowUp) => {
                            Some(Message::AutocompleteNavigate(AutocompleteNav::Up))
                        }
                        Key::Named(key::Named::Enter) | Key::Named(key::Named::Tab) => {
                            Some(Message::AutocompleteNavigate(AutocompleteNav::Select))
                        }
                        Key::Named(key::Named::Escape) => {
                            Some(Message::AutocompleteNavigate(AutocompleteNav::Escape))
                        }
                        _ => None,
                    }                    
                }
                _ => { None }
            }
        );

        Subscription::batch(vec![tick, keyboard])
    }

    fn generate_autocomplete(&self) -> Vec<AutocompleteOption> {
        if self.filter_text_staged.is_empty() {
            return vec![];
        }

        let mut suggestions = Vec::new();
        
        // Get unique values from current data
        if let DataState::Loaded(Ok(sockets)) = &self.process_info {
            let last_token = self.filter_text_staged
                .split_whitespace()
                .last()
                .unwrap_or("");

            // Check if typing a field name
            if last_token.contains(':') {
                let (field, partial) = last_token.split_once(':').unwrap();
                let partial_lower = partial.to_lowercase();
                
                let mut values = std::collections::HashSet::new();
                
                for socket in sockets {
                    let value = match field.to_lowercase().as_str() {
                        "protocol" | "proto" => &socket.protocol,
                        "process" | "proc" => &socket.process_name,
                        "state" => &socket.state,
                        _ => continue,
                    };
                    
                    if value.to_lowercase().contains(&partial_lower) {
                        values.insert(value.clone());
                    }
                }
                
                for value in values {
                    suggestions.push(AutocompleteOption {
                        display: format!("{}:{}", field, value),
                        insert: format!("{}:{}", field, value),
                    });
                }
            } else {
                // Suggest field names
                let field_names = vec![
                    "protocol:", "process:", "state:", 
                    "local:", "remote:", "pid:"
                ];
                
                for field in field_names {
                    if field.starts_with(&last_token.to_lowercase()) {
                        suggestions.push(AutocompleteOption {
                            display: field.to_string(),
                            insert: field.to_string(),
                        });
                    }
                }
            }
        }
        
        suggestions.truncate(10); // Limit to 10 suggestions
        suggestions
    }
}

pub fn main() -> iced::Result {
    iced::application(App::new, App::update, App::view)
        .theme(App::theme)
        .title(App::title)
        .subscription(App::subscription)
        .window(App::window_settings())
        .font(icon::FONT)
        .run()
}

fn get_netstat(system: &mut System) -> Result<Vec<SocketInfo>, Error> {
    system.refresh_processes(ProcessesToUpdate::All, true);

    // Get all TCP and UDP sockets for IPv4 and IPv6
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    get_sockets_info(af_flags, proto_flags)
}

#[derive(Debug, Clone)]
struct AutocompleteOption {
    display: String,
    insert: String,
}

#[derive(Debug, Clone)]
enum AutocompleteNav {
    Up,
    Down,
    Select,
    Escape,
}

#[derive(Debug, Clone)]
enum Token {
    OpenParen,
    CloseParen,
    Or,
    Not,
    Criterion(FilterCriterion),
}

#[derive(Debug, Clone)]
enum FilterExpr {
    And(Vec<FilterExpr>),
    Or(Vec<FilterExpr>),
    Not(Box<FilterExpr>),
    Criterion(FilterCriterion),
}

impl FilterExpr {
    fn matches(&self, socket: &SocketDisplay) -> bool {
        match self {
            FilterExpr::And(exprs) => exprs.iter().all(|e| e.matches(socket)),
            FilterExpr::Or(exprs) => exprs.iter().any(|e| e.matches(socket)),
            FilterExpr::Not(expr) => !expr.matches(socket),
            FilterExpr::Criterion(criterion) => criterion.matches(socket),
        }
    }
}

#[derive(Debug, Clone)]
enum FilterCriterion {
    Protocol(FilterMatch),
    Process(FilterMatch),
    State(FilterMatch),
    LocalAddr(FilterMatch),
    RemoteAddr(FilterMatch),
    Pid(FilterMatch),
    Any(FilterMatch),
}

impl FilterCriterion {
    fn field_name(&self) -> String {
        match self {
            FilterCriterion::Protocol(_) => "protocol".to_string(),
            FilterCriterion::Process(_) => "process".to_string(),
            FilterCriterion::State(_) => "state".to_string(),
            FilterCriterion::LocalAddr(_) => "local".to_string(),
            FilterCriterion::RemoteAddr(_) => "remote".to_string(),
            FilterCriterion::Pid(_) => "pid".to_string(),
            FilterCriterion::Any(_) => "any".to_string(),
        }
    }

    fn matches(&self, socket: &SocketDisplay) -> bool {
        match self {
            FilterCriterion::Protocol(m) => m.matches(&socket.protocol),
            FilterCriterion::Process(m) => m.matches(&socket.process_name),
            FilterCriterion::State(m) => m.matches(&socket.state),
            FilterCriterion::LocalAddr(m) => m.matches(&socket.local_addr),
            FilterCriterion::RemoteAddr(m) => m.matches(&socket.remote_addr),
            FilterCriterion::Pid(m) => m.matches(&socket.pid),
            FilterCriterion::Any(m) => {
                m.matches(&socket.protocol)
                    || m.matches(&socket.process_name)
                    || m.matches(&socket.state)
                    || m.matches(&socket.local_addr)
                    || m.matches(&socket.remote_addr)
                    || m.matches(&socket.pid)
            }
        }
    }
}

#[derive(Debug, Clone)]
enum FilterMatch {
    Exact(String),      // "System" - exact match
    Contains(String),   // *System* - contains
    StartsWith(String), // System* - starts with
    EndsWith(String),   // *System - ends with
}

impl FilterMatch {
    fn matches(&self, value: &str) -> bool {
        let value_lower = value.to_lowercase();
        match self {
            FilterMatch::Exact(s) => value_lower == s.to_lowercase(),
            FilterMatch::Contains(s) => value_lower.contains(&s.to_lowercase()),
            FilterMatch::StartsWith(s) => value_lower.starts_with(&s.to_lowercase()),
            FilterMatch::EndsWith(s) => value_lower.ends_with(&s.to_lowercase()),
        }
    }
    
    fn from_pattern(pattern: &str) -> Self {
        // Check if pattern is quoted
        let is_quoted = pattern.starts_with('"') && pattern.ends_with('"');
        
        let clean_pattern = if is_quoted {
            // Remove quotes for exact match
            pattern.trim_matches('"').to_string()
        } else {
            pattern.to_string()
        };
        
        let starts_with_wildcard = clean_pattern.starts_with('*');
        let ends_with_wildcard = clean_pattern.ends_with('*');
        
        // If quoted and no wildcards, treat as exact match
        if is_quoted && !starts_with_wildcard && !ends_with_wildcard {
            return FilterMatch::Exact(clean_pattern);
        }
        
        // If not quoted and no explicit wildcards, add them automatically
        if !is_quoted && !starts_with_wildcard && !ends_with_wildcard {
            return FilterMatch::Contains(clean_pattern);
        }
        
        // Otherwise handle explicit wildcards
        match (starts_with_wildcard, ends_with_wildcard) {
            (true, true) => {
                FilterMatch::Contains(clean_pattern.trim_matches('*').to_string())
            }
            (true, false) => {
                FilterMatch::EndsWith(clean_pattern.trim_start_matches('*').to_string())
            }
            (false, true) => {
                FilterMatch::StartsWith(clean_pattern.trim_end_matches('*').to_string())
            }
            (false, false) => {
                FilterMatch::Exact(clean_pattern)
            }
        }
    }
}

fn parse_filter(input: &str) -> FilterExpr {
    let tokens = tokenize(input);
    parse_expression(&tokens, 0).0
}

fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch); // Keep the quote in the string
            }
            '(' if !in_quotes => {
                if !current.is_empty() {
                    tokens.push(Token::Criterion(parse_single_criterion(&current)));
                    current.clear();
                }
                tokens.push(Token::OpenParen);
            }
            ')' if !in_quotes => {
                if !current.is_empty() {
                    tokens.push(Token::Criterion(parse_single_criterion(&current)));
                    current.clear();
                }
                tokens.push(Token::CloseParen);
            }
            '|' if !in_quotes => {
                if !current.is_empty() {
                    tokens.push(Token::Criterion(parse_single_criterion(&current)));
                    current.clear();
                }
                tokens.push(Token::Or);
            }
            '!' if !in_quotes => {
                if !current.is_empty() {
                    tokens.push(Token::Criterion(parse_single_criterion(&current)));
                    current.clear();
                }
                tokens.push(Token::Not);
            }
            ' ' if !in_quotes => {
                if !current.is_empty() {
                    tokens.push(Token::Criterion(parse_single_criterion(&current)));
                    current.clear();
                }
            }
            _ => {
                current.push(ch);
            }
        }
    }

    if !current.is_empty() {
        tokens.push(Token::Criterion(parse_single_criterion(&current)));
    }

    tokens
}

fn parse_expression(tokens: &[Token], pos: usize) -> (FilterExpr, usize) {
    if pos >= tokens.len() {
        return (FilterExpr::And(vec![]), pos);
    }

    let mut current_pos = pos;
    let mut or_groups: Vec<Vec<FilterExpr>> = vec![vec![]];
    let mut current_or_index = 0;

    while current_pos < tokens.len() {
        match &tokens[current_pos] {
            Token::Not => {
                current_pos += 1;
                if current_pos >= tokens.len() {
                    break;
                }
                
                // Parse the next expression to negate
                let (expr, new_pos) = match &tokens[current_pos] {
                    Token::OpenParen => {
                        parse_expression(tokens, current_pos + 1)
                    }
                    Token::Criterion(criterion) => {
                        (FilterExpr::Criterion(criterion.clone()), current_pos + 1)
                    }
                    _ => break,
                };
                
                or_groups[current_or_index].push(FilterExpr::Not(Box::new(expr)));
                current_pos = new_pos;
            }
            Token::OpenParen => {
                let (sub_expr, new_pos) = parse_expression(tokens, current_pos + 1);
                or_groups[current_or_index].push(sub_expr);
                current_pos = new_pos;
            }
            Token::CloseParen => {
                current_pos += 1;
                break;
            }
            Token::Or => {
                or_groups.push(vec![]);
                current_or_index += 1;
                current_pos += 1;
            }
            Token::Criterion(criterion) => {
                or_groups[current_or_index].push(FilterExpr::Criterion(criterion.clone()));
                current_pos += 1;
            }
        }
    }

    // Build the expression tree
    let result = if or_groups.len() > 1 {
        let or_exprs: Vec<FilterExpr> = or_groups
            .into_iter()
            .map(|group| {
                if group.len() == 1 {
                    group.into_iter().next().unwrap()
                } else {
                    FilterExpr::And(group)
                }
            })
            .collect();
        FilterExpr::Or(or_exprs)
    } else {
        let group = or_groups.into_iter().next().unwrap();
        if group.len() == 1 {
            group.into_iter().next().unwrap()
        } else {
            FilterExpr::And(group)
        }
    };

    (result, current_pos)
}

fn parse_single_criterion(input: &str) -> FilterCriterion {
    if let Some((prefix, value)) = input.split_once(':') {
        let filter_match = FilterMatch::from_pattern(value);
        match prefix.to_lowercase().as_str() {
            "protocol" | "proto" => FilterCriterion::Protocol(filter_match),
            "process" | "proc" => FilterCriterion::Process(filter_match),
            "state" => FilterCriterion::State(filter_match),
            "local" | "localaddr" => FilterCriterion::LocalAddr(filter_match),
            "remote" | "remoteaddr" => FilterCriterion::RemoteAddr(filter_match),
            "pid" => FilterCriterion::Pid(filter_match),
            _ => FilterCriterion::Any(FilterMatch::from_pattern(input)),
        }
    } else {
        FilterCriterion::Any(FilterMatch::from_pattern(input))
    }
}

fn optimize_filter(expr: FilterExpr) -> FilterExpr {
    match expr {
        FilterExpr::And(exprs) => {
            // Group criteria by field type
            let mut by_field: std::collections::HashMap<String, Vec<FilterCriterion>> = 
                std::collections::HashMap::new();
            let mut other_exprs = Vec::new();

            for e in exprs {
                match e {
                    FilterExpr::Criterion(criterion) => {
                        let field_name = criterion.field_name();
                        by_field.entry(field_name).or_insert_with(Vec::new).push(criterion);
                    }
                    other => other_exprs.push(optimize_filter(other)),
                }
            }

            // Convert fields with multiple criteria to OR
            let mut result = Vec::new();
            for (_, criteria) in by_field {
                if criteria.len() > 1 {
                    result.push(FilterExpr::Or(
                        criteria.into_iter().map(FilterExpr::Criterion).collect()
                    ));
                } else {
                    result.push(FilterExpr::Criterion(criteria.into_iter().next().unwrap()));
                }
            }
            result.extend(other_exprs);

            if result.len() == 1 {
                result.into_iter().next().unwrap()
            } else {
                FilterExpr::And(result)
            }
        }
        FilterExpr::Or(exprs) => {
            FilterExpr::Or(exprs.into_iter().map(optimize_filter).collect())
        }
        other => other,
    }
}