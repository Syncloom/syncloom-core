//! Client-side three-way merge for plain-text files.
//!
//! The server never sees plaintext, so merging always happens on a client.
pub const MAX_TEXT_SIZE: usize = 5 * 1024 * 1024;

/// Content-based text detection: valid UTF-8, no NUL bytes, bounded size.
pub fn is_text(data: &[u8]) -> bool {
    data.len() <= MAX_TEXT_SIZE && !data.contains(&0) && std::str::from_utf8(data).is_ok()
}

#[derive(Debug, PartialEq)]
pub enum MergeOutcome {
    Merged(Vec<u8>),
    /// Overlapping edits, or not text. The caller should create a conflict copy.
    Conflict,
}

pub fn merge(base: &[u8], local: &[u8], remote: &[u8]) -> MergeOutcome {
    if local == remote {
        return MergeOutcome::Merged(local.to_vec());
    }
    if local == base {
        return MergeOutcome::Merged(remote.to_vec());
    }
    if remote == base {
        return MergeOutcome::Merged(local.to_vec());
    }
    if !(is_text(base) && is_text(local) && is_text(remote)) {
        return MergeOutcome::Conflict;
    }
    let (b, l, r) = (
        std::str::from_utf8(base).unwrap(),
        std::str::from_utf8(local).unwrap(),
        std::str::from_utf8(remote).unwrap(),
    );
    match diffy::merge(b, l, r) {
        Ok(m) => MergeOutcome::Merged(m.into_bytes()),
        Err(_) => MergeOutcome::Conflict,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "one\ntwo\nthree\nfour\nfive\nsix\nseven\n";

    #[test]
    fn non_overlapping_edits_merge() {
        let local = BASE.replace("one", "ONE");
        let remote = BASE.replace("seven", "SEVEN");
        match merge(BASE.as_bytes(), local.as_bytes(), remote.as_bytes()) {
            MergeOutcome::Merged(m) => {
                let s = String::from_utf8(m).unwrap();
                assert!(s.contains("ONE") && s.contains("SEVEN"));
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn overlapping_edits_conflict() {
        let local = BASE.replace("three", "local");
        let remote = BASE.replace("three", "remote");
        assert_eq!(merge(BASE.as_bytes(), local.as_bytes(), remote.as_bytes()), MergeOutcome::Conflict);
    }

    #[test]
    fn trivial_cases_and_binary() {
        assert_eq!(merge(b"a", b"b", b"b"), MergeOutcome::Merged(b"b".to_vec()));
        assert_eq!(merge(b"a", b"a", b"c"), MergeOutcome::Merged(b"c".to_vec()));
        assert_eq!(merge(b"a", b"b", b"a"), MergeOutcome::Merged(b"b".to_vec()));
        assert_eq!(merge(b"a\0", b"b\0", b"c\0"), MergeOutcome::Conflict);
        assert!(!is_text(&[0xff, 0xfe]));
        assert!(is_text("héllo".as_bytes()));
    }
}
