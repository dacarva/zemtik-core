use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use zemtik::openai::query_openai;

#[tokio::test]
async fn test_query_openai_body_read_failure() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&mock_server)
        .await;

    let result = query_openai(
        1000,
        "aws_spend",
        "2024-01-01",
        "2024-03-31",
        Some("test-api-key"),
        Some(&mock_server.uri()),
    )
    .await;

    assert!(result.is_err(), "expected Err for HTTP 500, got Ok");
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("500"),
        "expected HTTP status code 500 in error message, got: {}",
        msg
    );
}

#[tokio::test]
async fn test_query_openai_error_includes_status() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(429).set_body_string("rate limited"))
        .mount(&mock_server)
        .await;

    let result = query_openai(
        500,
        "aws_spend",
        "2024-01-01",
        "2024-03-31",
        Some("test-api-key"),
        Some(&mock_server.uri()),
    )
    .await;

    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("429"),
        "expected 429 in error message, got: {}",
        msg
    );
}
