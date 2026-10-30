//! File-name normalization and collision handling across macOS / Windows / Linux.
use crate::error::{Error, Result};
use unicode_normalization::UnicodeNormalization;

const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1",
    "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];
const FORBIDDEN_CHARS: &[char] = &['<', '>', ':', '"', '/', '\\', '|', '?', '*'];

/// Canonical form used for storage and comparison (Unicode NFC).
pub fn normalize(name: &str) -> String {
    name.nfc().collect()
}

/// Key under which two names collide on a case-insensitive file system.
pub fn collision_key(name: &str) -> String {
    normalize(name).to_lowercase()
}

/// Names that cannot be created on *some* supported OS are rejected up-front so that a
/// file created on Linux never becomes un-syncable on Windows.
pub fn validate(name: &str) -> Result<()> {
    let bad = |m: &str| Err(Error::Invalid(format!("invalid file name {name:?}: {m}")));
    if name.is_empty() || name == "." || name == ".." {
        return bad("empty or dot name");
    }
    if name.len() > 255 {
        return bad("longer than 255 bytes");
    }
    if let Some(c) = name.chars().find(|c| FORBIDDEN_CHARS.contains(c) || c.is_control()) {
        return bad(&format!("contains forbidden character {c:?}"));
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return bad("ends with dot or space");
    }
    let stem = name.split('.').next().unwrap_or("").to_uppercase();
    if WINDOWS_RESERVED.contains(&stem.as_str()) {
        return bad("reserved on Windows");
    }
    Ok(())
}

/// Find an existing sibling that collides with `name` (exact or case/normalization-insensitive).
pub fn find_collision<'a>(existing: impl IntoIterator<Item = &'a str>, name: &str) -> Option<&'a str> {
    let k = collision_key(name);
    existing.into_iter().find(|e| collision_key(e) == k)
}

fn split_ext(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    }
}

/// `report.txt` -> `report (conflict – laptop – 2026-10-29).txt`
pub fn conflict_name(name: &str, device: &str, date: &str) -> String {
    let (stem, ext) = split_ext(name);
    format!("{stem} (conflict – {device} – {date}){ext}")
}

/// Pick a name based on `desired` that does not collide with any of `existing`.
pub fn unique_name<'a>(existing: impl IntoIterator<Item = &'a str> + Clone, desired: &str) -> String {
    if find_collision(existing.clone(), desired).is_none() {
        return desired.to_string();
    }
    let (stem, ext) = split_ext(desired);
    for i in 2.. {
        let cand = format!("{stem} ({i}){ext}");
        if find_collision(existing.clone(), &cand).is_none() {
            return cand;
        }
    }
    unreachable!()
}

/// Make an arbitrary name safe for the local OS rules by replacing offending parts.
pub fn sanitize(name: &str) -> String {
    let mut s: String = normalize(name)
        .chars()
        .map(|c| if FORBIDDEN_CHARS.contains(&c) || c.is_control() { '_' } else { c })
        .collect();
    while s.ends_with('.') || s.ends_with(' ') {
        s.pop();
    }
    if s.is_empty() {
        s = "_".into();
    }
    let stem = s.split('.').next().unwrap_or("").to_uppercase();
    if WINDOWS_RESERVED.contains(&stem.as_str()) {
        s.insert(0, '_');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nfc_nfd_collide() {
        let nfd = "e\u{0301}.txt"; // e + combining acute
        let nfc = "\u{00e9}.txt";
        assert_ne!(nfd, nfc);
        assert_eq!(normalize(nfd), nfc);
        assert!(find_collision([nfc], nfd).is_some());
    }

    #[test]
    fn case_collision() {
        assert_eq!(find_collision(["Readme.MD", "x"], "readme.md"), Some("Readme.MD"));
        assert_eq!(find_collision(["a"], "b"), None);
    }

    #[test]
    fn validation() {
        assert!(validate("ok.txt").is_ok());
        for bad in ["", "..", "a/b", "a:b", "con", "NUL.txt", "trail.", "trail ", "tab\t"] {
            assert!(validate(bad).is_err(), "{bad:?} should be invalid");
        }
        assert!(validate(&"x".repeat(256)).is_err());
        assert!(validate("console.txt").is_ok());
    }

    #[test]
    fn conflict_and_unique() {
        assert_eq!(conflict_name("a.tar.gz", "mac", "2026-10-29"), "a.tar (conflict – mac – 2026-10-29).gz");
        assert_eq!(conflict_name("noext", "d", "t"), "noext (conflict – d – t)");
        assert_eq!(conflict_name(".hidden", "d", "t"), ".hidden (conflict – d – t)");
        assert_eq!(unique_name(["a.txt", "A (2).txt"], "a.txt"), "a (3).txt");
        assert_eq!(unique_name(["x"], "y"), "y");
    }

    #[test]
    fn sanitize_names() {
        assert_eq!(sanitize("a:b?.txt"), "a_b_.txt");
        assert_eq!(sanitize("con"), "_con");
        assert_eq!(sanitize("..."), "_");
        assert!(validate(&sanitize("a:b?.txt")).is_ok());
    }
}
