use zemtik::types::{ContentPart, MessageContent};

#[test]
fn string_content_returned_unchanged() {
    let mc = MessageContent::Text("Q1 payroll?".to_owned());
    assert_eq!(mc.to_text(), "Q1 payroll?");
}

#[test]
fn parts_text_only_joined() {
    let mc = MessageContent::Parts(vec![
        ContentPart { kind: "text".into(), text: Some("Q1".into()) },
        ContentPart { kind: "text".into(), text: Some(" payroll".into()) },
    ]);
    assert_eq!(mc.to_text(), "Q1 payroll");
}

#[test]
fn parts_mixed_drops_non_text() {
    let mc = MessageContent::Parts(vec![
        ContentPart { kind: "text".into(), text: Some("Q1".into()) },
        ContentPart { kind: "image_url".into(), text: None },
    ]);
    assert_eq!(mc.to_text(), "Q1");
}

#[test]
fn parts_empty_returns_empty() {
    let mc = MessageContent::Parts(vec![]);
    assert_eq!(mc.to_text(), "");
}

#[test]
fn parts_all_non_text_returns_empty() {
    let mc = MessageContent::Parts(vec![
        ContentPart { kind: "image_url".into(), text: None },
    ]);
    assert_eq!(mc.to_text(), "");
}

#[test]
fn deserialize_string_content() {
    let json = r#""hello world""#;
    let mc: MessageContent = serde_json::from_str(json).unwrap();
    assert_eq!(mc.to_text(), "hello world");
}

#[test]
fn deserialize_parts_content() {
    let json = r#"[{"type":"text","text":"Q1"},{"type":"text","text":" payroll"}]"#;
    let mc: MessageContent = serde_json::from_str(json).unwrap();
    assert_eq!(mc.to_text(), "Q1 payroll");
}
