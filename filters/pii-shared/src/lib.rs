//! Shared PII detection and redaction logic, extracted from `pii-default`
//! so individual Wasm filter plugins can redact exactly one PII type.
//!
//! Pure Rust, no Wasm-only code — compiled natively for host unit tests and
//! into each wasm32 filter component that depends on it.

/// PII kinds that can be detected by [`find_spans`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PiiKind {
    Email,
    Card,
    Ssn,
}

impl PiiKind {
    fn marker(self) -> &'static str {
        match self {
            PiiKind::Email => "[REDACTED_EMAIL]",
            PiiKind::Card => "[REDACTED_CARD]",
            PiiKind::Ssn => "[REDACTED_SSN]",
        }
    }
}

/// Redact all supported PII kinds in a single pass (matching the original
/// combined filter; important for the sandbox fuel budget).
pub fn redact_pii(input: &str) -> String {
    replace_spans(input, &find_all_spans(input))
}

/// Locate spans of every supported PII kind in one scan.
pub fn find_all_spans(input: &str) -> Vec<(usize, usize, &'static str)> {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    let mut spans: Vec<(usize, usize, &'static str)> = Vec::new();

    while i < len {
        if bytes[i] == b'@'
            && let Some((start, end)) = find_email_boundary(bytes, i, len)
        {
            let candidate = &input[start..end];
            if is_valid_email(candidate) {
                spans.push((start, end, PiiKind::Email.marker()));
                i = end;
                continue;
            }
        }

        if bytes[i].is_ascii_digit()
            && let Some((start, end)) = find_digit_token(bytes, i, len)
        {
            let mut s = start;
            while s < end && !bytes[s].is_ascii_digit() {
                s += 1;
            }
            let mut e = end;
            while e > s && !bytes[e - 1].is_ascii_digit() {
                e -= 1;
            }
            if s >= e {
                i += 1;
                continue;
            }
            let candidate = &input[s..e];
            let digit_count = candidate.chars().filter(|c| c.is_ascii_digit()).count();

            if (13..=19).contains(&digit_count) {
                let digits_only: String =
                    candidate.chars().filter(|c| c.is_ascii_digit()).collect();
                if is_valid_card(&digits_only) {
                    spans.push((s, e, PiiKind::Card.marker()));
                    i = e;
                    continue;
                }
            }

            if digit_count == 9 && is_valid_ssn_format(candidate) {
                let digits_only: String =
                    candidate.chars().filter(|c| c.is_ascii_digit()).collect();
                if is_valid_ssn(&digits_only) {
                    spans.push((s, e, PiiKind::Ssn.marker()));
                    i = e;
                    continue;
                }
            }
        }

        i += 1;
    }
    spans
}

/// Redact only email addresses.
pub fn redact_emails(input: &str) -> String {
    replace_spans(input, &find_spans(input, PiiKind::Email))
}

/// Redact only credit card numbers.
pub fn redact_cards(input: &str) -> String {
    replace_spans(input, &find_spans(input, PiiKind::Card))
}

/// Redact only social security numbers.
pub fn redact_ssns(input: &str) -> String {
    replace_spans(input, &find_spans(input, PiiKind::Ssn))
}

/// Locate all spans of a single PII kind in `input`.
pub fn find_spans(input: &str, kind: PiiKind) -> Vec<(usize, usize, &'static str)> {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    let mut spans: Vec<(usize, usize, &'static str)> = Vec::new();

    while i < len {
        if kind == PiiKind::Email {
            if bytes[i] == b'@'
                && let Some((start, end)) = find_email_boundary(bytes, i, len)
            {
                let candidate = &input[start..end];
                if is_valid_email(candidate) {
                    spans.push((start, end, kind.marker()));
                    i = end;
                    continue;
                }
            }
        } else if bytes[i].is_ascii_digit()
            && let Some((start, end)) = find_digit_token(bytes, i, len)
        {
            let mut s = start;
            while s < end && !bytes[s].is_ascii_digit() {
                s += 1;
            }
            let mut e = end;
            while e > s && !bytes[e - 1].is_ascii_digit() {
                e -= 1;
            }
            if s >= e {
                i += 1;
                continue;
            }
            let candidate = &input[s..e];
            let digit_count = candidate.chars().filter(|c| c.is_ascii_digit()).count();

            if kind == PiiKind::Card {
                if (13..=19).contains(&digit_count) {
                    let digits_only: String =
                        candidate.chars().filter(|c| c.is_ascii_digit()).collect();
                    if is_valid_card(&digits_only) {
                        spans.push((s, e, kind.marker()));
                        i = e;
                        continue;
                    }
                }
            } else if digit_count == 9 && is_valid_ssn_format(candidate) {
                let digits_only: String =
                    candidate.chars().filter(|c| c.is_ascii_digit()).collect();
                if is_valid_ssn(&digits_only) {
                    spans.push((s, e, kind.marker()));
                    i = e;
                    continue;
                }
            }
        }
        i += 1;
    }
    spans
}

/// Apply replacement markers over `spans`, skipping any that overlap a span
/// already written (spans must be sorted by start for deterministic output).
pub fn replace_spans(input: &str, spans: &[(usize, usize, &'static str)]) -> String {
    let mut sorted: Vec<_> = spans.to_vec();
    sorted.sort_by_key(|(start, end, _)| (*start, *end));
    sorted.dedup_by_key(|(start, _, _)| *start);

    let mut output = String::with_capacity(input.len());
    let mut pos = 0;
    for (start, end, replacement) in &sorted {
        if *start < pos {
            continue;
        }
        output.push_str(&input[pos..*start]);
        output.push_str(replacement);
        pos = *end;
    }
    output.push_str(&input[pos..]);

    if output == input {
        input.to_string()
    } else {
        output
    }
}

fn find_digit_token(bytes: &[u8], start: usize, len: usize) -> Option<(usize, usize)> {
    let mut s = start;
    while s > 0 {
        let b = bytes[s - 1];
        if b.is_ascii_digit() || b == b' ' || b == b'-' {
            s -= 1;
        } else {
            break;
        }
    }
    let mut e = start;
    while e < len {
        let b = bytes[e];
        if b.is_ascii_digit() || b == b' ' || b == b'-' {
            e += 1;
        } else {
            break;
        }
    }
    if e <= s {
        return None;
    }
    let digit_count = bytes[s..e].iter().filter(|b| b.is_ascii_digit()).count();
    if digit_count == 0 {
        return None;
    }
    Some((s, e))
}

fn find_email_boundary(bytes: &[u8], at_pos: usize, len: usize) -> Option<(usize, usize)> {
    let mut s = at_pos;
    while s > 0
        && bytes[s - 1] != b' '
        && bytes[s - 1] != b'\n'
        && bytes[s - 1] != b'\r'
        && bytes[s - 1] != b'\t'
        && bytes[s - 1] != b','
        && bytes[s - 1] != b'"'
    {
        s -= 1;
    }
    let mut e = at_pos + 1;
    while e < len
        && bytes[e] != b' '
        && bytes[e] != b'\n'
        && bytes[e] != b'\r'
        && bytes[e] != b'\t'
        && bytes[e] != b','
        && bytes[e] != b'"'
    {
        e += 1;
    }
    if s < at_pos && e > at_pos + 1 {
        Some((s, e))
    } else {
        None
    }
}

pub fn is_valid_email(s: &str) -> bool {
    !s.is_empty() && s.contains('@') && s.contains('.') && s.len() <= 254
}

pub fn is_valid_card(digits: &str) -> bool {
    if digits.len() < 13 || digits.len() > 19 || !digits.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    luhn_check(digits)
}

fn luhn_check(s: &str) -> bool {
    let sum: u32 = s
        .chars()
        .rev()
        .enumerate()
        .map(|(i, c)| {
            let d = c.to_digit(10).unwrap_or(0);
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

pub fn is_valid_ssn_format(s: &str) -> bool {
    (s.len() == 9 && s.chars().all(|c| c.is_ascii_digit()))
        || (s.len() == 11
            && s.chars().nth(3) == Some('-')
            && s.chars().nth(6) == Some('-')
            && s[..3].chars().all(|c| c.is_ascii_digit())
            && s[4..6].chars().all(|c| c.is_ascii_digit())
            && s[7..].chars().all(|c| c.is_ascii_digit()))
}

pub fn is_valid_ssn(digits: &str) -> bool {
    if digits.len() != 9 || !digits.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let area: u32 = digits[..3].parse().unwrap_or(999);
    let group: u32 = digits[3..5].parse().unwrap_or(99);
    let serial: u32 = digits[5..].parse().unwrap_or(9999);

    if area == 0 || area == 666 || area > 899 || group == 0 || serial == 0 {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_email() {
        let input = "Contact alice@example.com for help.";
        let result = redact_pii(input);
        assert_eq!(result, "Contact [REDACTED_EMAIL] for help.");
    }

    #[test]
    fn redacts_ssn_with_dashes() {
        let input = "SSN: 123-45-6789";
        let result = redact_pii(input);
        assert_eq!(result, "SSN: [REDACTED_SSN]");
    }

    #[test]
    fn redacts_ssn_nine_digits() {
        let input = "SSN 078051120";
        let result = redact_pii(input);
        assert_eq!(result, "SSN [REDACTED_SSN]");
    }

    #[test]
    fn redacts_valid_card() {
        let input = "Card: 4111111111111111";
        let result = redact_pii(input);
        assert_eq!(result, "Card: [REDACTED_CARD]");
    }

    #[test]
    fn redacts_amex_card() {
        let input = "Amex 378282246310005";
        let result = redact_pii(input);
        assert_eq!(result, "Amex [REDACTED_CARD]");
    }

    #[test]
    fn preserves_non_luhn_digits() {
        let input = "Reference 1234567890123";
        let result = redact_pii(input);
        assert_eq!(result, "Reference 1234567890123");
    }

    #[test]
    fn invalid_ssn_area_not_redacted() {
        let input = "Bad SSN 000-12-3456";
        let result = redact_pii(input);
        assert_eq!(result, "Bad SSN 000-12-3456");
    }

    #[test]
    fn invalid_ssn_area_666_not_redacted() {
        let input = "Bad SSN 666-12-3456";
        let result = redact_pii(input);
        assert_eq!(result, "Bad SSN 666-12-3456");
    }

    #[test]
    fn invalid_ssn_area_900_not_redacted() {
        let input = "Bad SSN 900-12-3456";
        let result = redact_pii(input);
        assert_eq!(result, "Bad SSN 900-12-3456");
    }

    #[test]
    fn invalid_ssn_group_zero() {
        let input = "Bad SSN 123-00-4567";
        let result = redact_pii(input);
        assert_eq!(result, "Bad SSN 123-00-4567");
    }

    #[test]
    fn invalid_ssn_serial_zero() {
        let input = "Bad SSN 123-45-0000";
        let result = redact_pii(input);
        assert_eq!(result, "Bad SSN 123-45-0000");
    }

    #[test]
    fn multiple_pii_in_one_line() {
        let input = "alice@test.com SSN 123-45-6789 card 5500005555555559";
        let result = redact_pii(input);
        assert_eq!(
            result,
            "[REDACTED_EMAIL] SSN [REDACTED_SSN] card [REDACTED_CARD]"
        );
    }

    #[test]
    fn no_pii_unchanged() {
        let input = "No personal info here.";
        let result = redact_pii(input);
        assert_eq!(result, input);
    }

    #[test]
    fn empty_string() {
        assert_eq!(redact_pii(""), "");
    }

    #[test]
    fn unicode_unchanged_by_redaction() {
        let input = "Café au lait at café@example.com";
        let result = redact_pii(input);
        assert_eq!(result, "Café au lait at [REDACTED_EMAIL]");
    }

    #[test]
    fn is_valid_ssn_rejects_wrong_length() {
        assert!(!is_valid_ssn("12345678"));
        assert!(!is_valid_ssn("1234567890"));
    }

    #[test]
    fn is_valid_ssn_rejects_non_digits() {
        assert!(!is_valid_ssn("123-45-678"));
        assert!(!is_valid_ssn("12a456789"));
    }

    #[test]
    fn is_valid_ssn_accepts_valid() {
        assert!(is_valid_ssn("123456789"));
        assert!(is_valid_ssn("078051120"));
    }

    #[test]
    fn is_valid_card_validates_luhn() {
        assert!(is_valid_card("4111111111111111"));
        assert!(is_valid_card("5500005555555559"));
        assert!(is_valid_card("378282246310005"));
        assert!(!is_valid_card("1234567890123456"));
    }

    #[test]
    fn is_valid_card_rejects_short() {
        assert!(!is_valid_card("4111"));
        assert!(!is_valid_card("123456789012"));
    }

    #[test]
    fn is_valid_card_rejects_long() {
        assert!(!is_valid_card("12345678901234567890"));
    }

    #[test]
    fn is_valid_card_rejects_alpha() {
        assert!(!is_valid_card("4111a11111111111"));
    }

    #[test]
    fn card_with_spaces_detected() {
        let input = "Card 4111 1111 1111 1111 here";
        let result = redact_pii(input);
        assert_eq!(result, "Card [REDACTED_CARD] here");
    }

    #[test]
    fn card_with_dashes_detected() {
        let input = "Card 4111-1111-1111-1111 test";
        let result = redact_pii(input);
        assert_eq!(result, "Card [REDACTED_CARD] test");
    }

    #[test]
    fn deterministic_same_input_same_output() {
        let a = redact_pii("x@y.com 123-45-6789");
        let b = redact_pii("x@y.com 123-45-6789");
        assert_eq!(a, b);
    }

    #[test]
    fn redact_ssn_without_dashes() {
        let input = "ID 123456789 end";
        let result = redact_pii(input);
        assert_eq!(result, "ID [REDACTED_SSN] end");
    }

    #[test]
    fn nested_digit_token_card_then_ssn() {
        let input = "Card378282246310005 still here 123456789";
        let result = redact_pii(input);
        assert_eq!(result, "Card[REDACTED_CARD] still here [REDACTED_SSN]");
    }

    #[test]
    fn nine_digit_not_valid_ssn_not_redacted() {
        let input = "Num 999887766";
        let result = redact_pii(input);
        assert_eq!(result, "Num 999887766");
    }

    #[test]
    fn email_on_word_boundary() {
        assert_eq!(redact_pii("a@b.co is email"), "[REDACTED_EMAIL] is email");
    }

    #[test]
    fn redacts_email_in_text_with_newlines() {
        assert_eq!(
            redact_pii("hello\nuser@site.org\nworld"),
            "hello\n[REDACTED_EMAIL]\nworld"
        );
    }

    #[test]
    fn redact_emails_only_leaves_digits() {
        let input = "alice@test.com SSN 123-45-6789 card 5500005555555559";
        assert_eq!(
            redact_emails(input),
            "[REDACTED_EMAIL] SSN 123-45-6789 card 5500005555555559"
        );
    }

    #[test]
    fn redact_ssns_only_leaves_rest() {
        let input = "alice@test.com SSN 123-45-6789 card 5500005555555559";
        assert_eq!(
            redact_ssns(input),
            "alice@test.com SSN [REDACTED_SSN] card 5500005555555559"
        );
    }

    #[test]
    fn redact_cards_only_leaves_rest() {
        let input = "alice@test.com SSN 123-45-6789 card 5500005555555559";
        assert_eq!(
            redact_cards(input),
            "alice@test.com SSN 123-45-6789 card [REDACTED_CARD]"
        );
    }
}
