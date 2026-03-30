use zemtik::bundle::parse_bb_version;

#[test]
fn test_parse_bb_version_plain() {
    assert_eq!(parse_bb_version("4.0.0"), Some((4, 0, 0)));
}

#[test]
fn test_parse_bb_version_nightly_suffix() {
    assert_eq!(parse_bb_version("4.0.0-nightly"), Some((4, 0, 0)));
}

#[test]
fn test_parse_bb_version_bbup_prefix() {
    assert_eq!(parse_bb_version("bbup version 0.5.1"), Some((0, 5, 1)));
}

#[test]
fn test_parse_bb_version_empty() {
    assert_eq!(parse_bb_version(""), None);
}

#[test]
fn test_parse_bb_version_non_semver() {
    assert_eq!(parse_bb_version("invalid"), None);
    assert_eq!(parse_bb_version("4.0"), None);
}
