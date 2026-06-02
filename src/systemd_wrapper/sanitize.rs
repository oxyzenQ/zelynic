// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

pub(super) fn sanitize_scope_component(value: &str) -> String {
    let mut sanitized = String::new();
    let mut last_was_separator = false;

    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            sanitized.push(ch.to_ascii_lowercase());
            last_was_separator = false;
        } else if !last_was_separator && !sanitized.is_empty() {
            sanitized.push('_');
            last_was_separator = true;
        }
    }

    if sanitized.ends_with('_') {
        sanitized.pop();
    }

    if sanitized.is_empty() {
        "target".to_string()
    } else {
        sanitized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_component_sanitizes_unsafe_characters() {
        assert_eq!(sanitize_scope_component("helium"), "helium");
        assert_eq!(
            sanitize_scope_component("Helium Browser!"),
            "helium_browser"
        );
        assert_eq!(sanitize_scope_component("foo///bar"), "foo_bar");
        assert_eq!(sanitize_scope_component("///"), "target");
    }
}
