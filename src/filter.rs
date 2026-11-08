use crate::SocketDisplay;

pub(super) fn last_token_start(input: &str) -> usize {
    let (mut quoted, mut start) = (false, 0);
    for (i, c) in input.char_indices() {
        if c == '"' {
            quoted = !quoted;
        } else if !quoted && (c.is_whitespace() || matches!(c, '(' | ')' | '|' | '!')) {
            start = i + c.len_utf8();
        }
    }
    start
}
pub(super) fn quote_value(value: &str) -> String {
    if value
        .chars()
        .any(|c| c.is_whitespace() || matches!(c, '(' | ')' | '|' | '!'))
    {
        format!("\"{value}\"")
    } else {
        value.into()
    }
}
pub(super) fn completion_context(prefix: &str, field: &str) -> Option<FilterExpr> {
    fn remove(expr: FilterExpr, field: &str) -> Option<FilterExpr> {
        match expr {
            FilterExpr::Criterion(c) => {
                if c.field_name() == field {
                    None
                } else {
                    Some(FilterExpr::Criterion(c))
                }
            }
            FilterExpr::Not(e) => remove(*e, field).map(|e| FilterExpr::Not(Box::new(e))),
            FilterExpr::And(v) => {
                let v: Vec<_> = v.into_iter().filter_map(|e| remove(e, field)).collect();
                (!v.is_empty()).then_some(FilterExpr::And(v))
            }
            FilterExpr::Or(v) => {
                let v: Vec<_> = v.into_iter().filter_map(|e| remove(e, field)).collect();
                (!v.is_empty()).then_some(FilterExpr::Or(v))
            }
        }
    }
    if prefix.trim().is_empty() || validate(prefix).is_err() {
        None
    } else {
        remove(optimize_filter(parse_filter(prefix)), field)
    }
}

pub(super) fn validate(input: &str) -> Result<(), String> {
    if input.len() > 4096 {
        return Err("Filter exceeds 4096 bytes".into());
    }
    if input.chars().filter(|c| *c == '"').count() % 2 != 0 {
        return Err("Close the quoted filter value".into());
    }
    let tokens = tokenize(input);
    if tokens.len() > 512 {
        return Err("Too many filter terms".into());
    }
    let (mut depth, mut needs_term, mut pending_not) = (0usize, true, false);
    for token in tokens {
        match token {
            Token::OpenParen => {
                depth += 1;
                if depth > 32 {
                    return Err("Filter nesting exceeds 32 levels".into());
                }
                needs_term = true;
                pending_not = false;
            }
            Token::CloseParen => {
                if depth == 0 || needs_term {
                    return Err("Unexpected or empty closing parenthesis".into());
                }
                depth -= 1;
                needs_term = false;
                pending_not = false;
            }
            Token::Or => {
                if needs_term {
                    return Err("OR needs values on both sides".into());
                }
                needs_term = true;
                pending_not = false;
            }
            Token::Not => {
                if pending_not {
                    return Err("Use one negation per value or group".into());
                }
                needs_term = true;
                pending_not = true;
            }
            Token::Criterion(_) => {
                needs_term = false;
                pending_not = false;
            }
        }
    }
    if depth != 0 {
        return Err("Close the filter parentheses".into());
    }
    if needs_term && !input.trim().is_empty() {
        return Err("Complete the filter expression".into());
    }
    Ok(())
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

pub(super) enum FilterExpr {
    And(Vec<FilterExpr>),

    Or(Vec<FilterExpr>),

    Not(Box<FilterExpr>),

    Criterion(FilterCriterion),
}

impl FilterExpr {
    pub(super) fn matches(&self, socket: &SocketDisplay) -> bool {
        match self {
            FilterExpr::And(exprs) => exprs.iter().all(|e| e.matches(socket)),

            FilterExpr::Or(exprs) => exprs.iter().any(|e| e.matches(socket)),

            FilterExpr::Not(expr) => !expr.matches(socket),

            FilterExpr::Criterion(criterion) => criterion.matches(socket),
        }
    }
}

#[derive(Debug, Clone)]

pub(super) enum FilterCriterion {
    Port(FilterMatch),

    Protocol(FilterMatch),

    Process(FilterMatch),

    State(FilterMatch),

    LocalAddr(FilterMatch),

    RemoteAddr(FilterMatch),

    Pid(FilterMatch),

    Any(FilterMatch),
}

impl FilterCriterion {
    pub(super) fn field_name(&self) -> String {
        match self {
            FilterCriterion::Port(_) => "port".to_string(),

            FilterCriterion::Protocol(_) => "protocol".to_string(),

            FilterCriterion::Process(_) => "process".to_string(),

            FilterCriterion::State(_) => "state".to_string(),

            FilterCriterion::LocalAddr(_) => "local".to_string(),

            FilterCriterion::RemoteAddr(_) => "remote".to_string(),

            FilterCriterion::Pid(_) => "pid".to_string(),

            FilterCriterion::Any(_) => "any".to_string(),
        }
    }

    pub(super) fn matches(&self, socket: &SocketDisplay) -> bool {
        match self {
            FilterCriterion::Port(m) => [&socket.local_addr, &socket.remote_addr].iter().any(|a| {
                a.parse::<std::net::SocketAddr>()
                    .ok()
                    .is_some_and(|a| m.matches(&a.port().to_string()))
            }),

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

pub(super) enum FilterMatch {
    Exact(String), // "System" - exact match

    Contains(String), // *System* - contains

    StartsWith(String), // System* - starts with

    EndsWith(String), // *System - ends with
}

impl FilterMatch {
    pub(super) fn matches(&self, value: &str) -> bool {
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
            (true, true) => FilterMatch::Contains(clean_pattern.trim_matches('*').to_string()),

            (true, false) => {
                FilterMatch::EndsWith(clean_pattern.trim_start_matches('*').to_string())
            }

            (false, true) => {
                FilterMatch::StartsWith(clean_pattern.trim_end_matches('*').to_string())
            }

            (false, false) => FilterMatch::Exact(clean_pattern),
        }
    }
}

pub(super) fn parse_filter(input: &str) -> FilterExpr {
    if validate(input).is_err() {
        return FilterExpr::Not(Box::new(FilterExpr::And(vec![])));
    }

    let tokens = tokenize(input);

    parse_expression(&tokens, 0).0
}

fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();

    let mut current = String::new();

    let mut in_quotes = false;

    for ch in input.chars() {
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
                    Token::OpenParen => parse_expression(tokens, current_pos + 1),

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

pub(super) fn parse_single_criterion(input: &str) -> FilterCriterion {
    if let Some((prefix, value)) = input.split_once(':') {
        let filter_match = FilterMatch::from_pattern(value);

        match prefix.to_lowercase().as_str() {
            "port" => FilterCriterion::Port(if value.parse::<u16>().is_ok() {
                FilterMatch::Exact(value.to_string())
            } else {
                filter_match
            }),

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

pub(super) fn optimize_filter(expr: FilterExpr) -> FilterExpr {
    match expr {
        FilterExpr::And(exprs) => {
            // Group criteria by field type

            let mut by_field: std::collections::BTreeMap<String, Vec<FilterCriterion>> =
                std::collections::BTreeMap::new();

            let mut other_exprs = Vec::new();

            for e in exprs {
                match e {
                    FilterExpr::Criterion(criterion) => {
                        let field_name = criterion.field_name();

                        by_field.entry(field_name).or_default().push(criterion);
                    }

                    other => other_exprs.push(optimize_filter(other)),
                }
            }

            // Convert fields with multiple criteria to OR

            let mut result = Vec::new();

            for (_, criteria) in by_field {
                if criteria.len() > 1 {
                    result.push(FilterExpr::Or(
                        criteria.into_iter().map(FilterExpr::Criterion).collect(),
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

        FilterExpr::Or(exprs) => FilterExpr::Or(exprs.into_iter().map(optimize_filter).collect()),

        FilterExpr::Not(expr) => FilterExpr::Not(Box::new(optimize_filter(*expr))),

        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn socket() -> SocketDisplay {
        SocketDisplay {
            key: None,
            protocol: "TCP".into(),
            state: "Listen".into(),
            local_addr: "0.0.0.0:5001".into(),
            remote_addr: "[::1]:42".into(),
            pid: "12".into(),
            process_name: "IFC8.exe".into(),
        }
    }
    #[test]
    fn filter_grammar_and_aliases() {
        for (query, expected) in [
            ("", true),
            ("proto:tcp proc:ifc8", true),
            ("protocol:udp | proc:ifc8", true),
            ("proc:other proc:ifc8 state:Listen", true),
            ("!(proto:udp | state:Established)", true),
            ("!(proc:other proc:ifc8)", false),
            ("proc:\"IFC8.exe\"", true),
            ("proc:\"IFC8\"", false),
            ("proc:IFC*", true),
            ("proc:*.exe", true),
            ("localaddr:5001 remoteaddr:::1 pid:12", true),
            ("port:5001", true),
            ("port:500", false),
            ("port:42", true),
            ("unknown:5001", false),
            ("!proc:ifc8", false),
        ] {
            assert!(validate(query).is_ok(), "{query}");
            assert_eq!(
                optimize_filter(parse_filter(query)).matches(&socket()),
                expected,
                "{query}"
            );
        }
    }
    #[test]
    fn invalid_filters_never_match_everything() {
        for q in ["(", ")", "()", "proc:a |", "| proc:a", "!!proc:a", "\"a"] {
            assert!(validate(q).is_err(), "{q}");
            assert!(!parse_filter(q).matches(&socket()));
        }
        assert!(validate(&"(".repeat(33)).is_err());
        assert!(validate(&"x".repeat(4097)).is_err());
    }
    #[test]
    fn matching_is_case_insensitive_and_not_an_interior_glob() {
        assert!(optimize_filter(parse_filter("proc:ifc8.EXE")).matches(&socket()));
        assert!(!optimize_filter(parse_filter("proc:I*8.exe")).matches(&socket()));
    }
}
