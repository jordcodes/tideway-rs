//! Shared helpers for locating and mutating `App` builder declarations in `main.rs`.

const APP_BUILDER_START_MARKER: &str = "tideway:app-builder:start";
const APP_BUILDER_END_MARKER: &str = "tideway:app-builder:end";

pub fn find_app_builder_marker_range(contents: &str) -> Option<(usize, usize)> {
    let start_marker = contents.find(APP_BUILDER_START_MARKER)?;
    let start = contents[start_marker..]
        .find('\n')
        .map(|idx| start_marker + idx + 1)?;

    let end_marker = contents.find(APP_BUILDER_END_MARKER)?;
    if end_marker <= start {
        return None;
    }

    let end = contents[..end_marker]
        .rfind('\n')
        .map(|idx| idx + 1)
        .unwrap_or(end_marker);
    Some((start, end))
}

pub fn find_app_builder_start(contents: &str) -> Option<usize> {
    if let Some((start, _)) = find_app_builder_marker_range(contents) {
        return Some(start);
    }
    let mut search_from = 0;
    while let Some(rel_pos) = contents[search_from..].find(" = App::") {
        let abs_pos = search_from + rel_pos;
        let line_start = contents[..abs_pos]
            .rfind('\n')
            .map(|idx| idx + 1)
            .unwrap_or(0);
        if find_app_builder_var_name(contents, line_start).is_some() {
            return Some(line_start);
        }
        search_from = abs_pos + 1;
    }
    None
}

pub fn find_unmarked_app_builder_statement_range(contents: &str) -> Option<(usize, usize)> {
    let mut search_from = 0;
    while let Some(rel_pos) = contents[search_from..].find(" = App::") {
        let abs_pos = search_from + rel_pos;
        let line_start = contents[..abs_pos]
            .rfind('\n')
            .map(|idx| idx + 1)
            .unwrap_or(0);
        if is_app_builder_start_line(&contents[line_start..]) {
            if let Some(end) = find_statement_terminator(contents, line_start) {
                return Some((line_start, end));
            }
        }
        search_from = abs_pos + 1;
    }
    None
}

pub fn find_app_builder_end_insert_at(contents: &str, start_pos: usize) -> Option<usize> {
    if let Some(marker_pos) = contents.find(APP_BUILDER_END_MARKER) {
        if marker_pos >= start_pos {
            let marker_line_start = contents[..marker_pos]
                .rfind('\n')
                .map(|idx| idx + 1)
                .unwrap_or(0);
            if let Some(marker_line_end_rel) = contents[marker_line_start..].find('\n') {
                return Some(marker_line_start + marker_line_end_rel + 1);
            }
            return Some(contents.len());
        }
    }
    find_statement_terminator(contents, start_pos).map(|idx| idx + 1)
}

pub fn find_app_builder_var_name(contents: &str, start_pos: usize) -> Option<String> {
    let line_end = contents[start_pos..]
        .find('\n')
        .map(|idx| start_pos + idx)
        .unwrap_or(contents.len());
    let line = contents[start_pos..line_end].trim();

    if !line.starts_with("let ") || !line.contains("= App::") {
        return None;
    }

    let after_let = line.trim_start_matches("let ").trim();
    let before_eq = after_let.split('=').next()?.trim();
    let var = before_eq.strip_prefix("mut ").unwrap_or(before_eq).trim();
    if var.is_empty() {
        None
    } else {
        Some(var.to_string())
    }
}

pub fn is_app_builder_start_line(line_and_rest: &str) -> bool {
    let line = line_and_rest.lines().next().unwrap_or("").trim();
    line.starts_with("let ") && line.contains(" = App::")
}

pub fn insert_snippet_into_builder_block(statement: &str, snippet: &str) -> Option<String> {
    let semicolon_pos = statement.rfind(';')?;
    let line_start = statement[..semicolon_pos]
        .rfind('\n')
        .map(|idx| idx + 1)
        .unwrap_or(0);
    let indent = statement[line_start..semicolon_pos]
        .chars()
        .take_while(|c| c.is_whitespace())
        .collect::<String>();
    let indent = if indent.is_empty() {
        "        ".to_string()
    } else {
        indent
    };

    let mut updated = String::with_capacity(statement.len() + snippet.len() + indent.len() + 8);
    updated.push_str(&statement[..semicolon_pos]);
    for line in snippet.lines() {
        updated.push('\n');
        updated.push_str(&indent);
        updated.push_str(line);
    }
    updated.push_str(&statement[semicolon_pos..]);

    Some(updated)
}

pub fn find_statement_terminator(contents: &str, start_pos: usize) -> Option<usize> {
    let bytes = contents.as_bytes();
    let mut i = start_pos;
    let mut paren_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escape = false;

    while i < bytes.len() {
        let b = bytes[i];

        // Skip line comments.
        if !in_single_quote
            && !in_double_quote
            && i + 1 < bytes.len()
            && bytes[i] == b'/'
            && bytes[i + 1] == b'/'
        {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        if escape {
            escape = false;
            i += 1;
            continue;
        }

        if in_single_quote {
            if b == b'\\' {
                escape = true;
            } else if b == b'\'' {
                in_single_quote = false;
            }
            i += 1;
            continue;
        }

        if in_double_quote {
            if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_double_quote = false;
            }
            i += 1;
            continue;
        }

        match b {
            b'\'' => in_single_quote = true,
            b'"' => in_double_quote = true,
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'{' => brace_depth += 1,
            b'}' => brace_depth = brace_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b';' if paren_depth == 0 && brace_depth == 0 && bracket_depth == 0 => return Some(i),
            _ => {}
        }

        i += 1;
    }
    None
}
