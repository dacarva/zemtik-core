use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};
use zemtik::db::{compute_tx_commitment, fr_to_decimal, query_sum_by_category, BATCH_SIZE, Q1_START};
use zemtik::types::Transaction;

fn make_rows(n: usize, amount: i64) -> serde_json::Value {
    let rows: Vec<_> = (0..n).map(|_| serde_json::json!({"amount": amount})).collect();
    serde_json::Value::Array(rows)
}

#[tokio::test]
async fn single_page_sum_correct() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/v1/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(make_rows(3, 100)))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let (sum, count) = query_sum_by_category(&client, &server.uri(), "key", "transactions", "aws", 123, 0, 9999).await.unwrap();
    assert_eq!(sum, 300);
    assert_eq!(count, 3);
}

#[tokio::test]
async fn string_amounts_parsed() {
    let server = MockServer::start().await;
    let rows = serde_json::json!([{"amount": "12345"}]);
    Mock::given(method("GET"))
        .and(path("/rest/v1/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(rows))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let (sum, count) = query_sum_by_category(&client, &server.uri(), "key", "transactions", "aws", 123, 0, 9999).await.unwrap();
    assert_eq!(sum, 12345);
    assert_eq!(count, 1);
}

#[tokio::test]
async fn null_amount_skipped() {
    let server = MockServer::start().await;
    let rows = serde_json::json!([{"amount": null}]);
    Mock::given(method("GET"))
        .and(path("/rest/v1/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(rows))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let (sum, count) = query_sum_by_category(&client, &server.uri(), "key", "transactions", "aws", 123, 0, 9999).await.unwrap();
    assert_eq!(sum, 0);
    assert_eq!(count, 1);
}

#[tokio::test]
async fn empty_result_returns_zero() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/v1/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let (sum, count) = query_sum_by_category(&client, &server.uri(), "key", "transactions", "aws", 123, 0, 9999).await.unwrap();
    assert_eq!(sum, 0);
    assert_eq!(count, 0);
}

#[tokio::test]
async fn pagination_exactly_1000_boundary() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/v1/transactions"))
        .and(wiremock::matchers::header("range", "0-999"))
        .respond_with(ResponseTemplate::new(200).set_body_json(make_rows(1000, 1)))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/v1/transactions"))
        .and(wiremock::matchers::header("range", "1000-1999"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let (sum, count) = query_sum_by_category(&client, &server.uri(), "key", "transactions", "aws", 123, 0, 9999).await.unwrap();
    assert_eq!(sum, 1000);
    assert_eq!(count, 1000);
}

#[tokio::test]
async fn pagination_two_pages() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/v1/transactions"))
        .and(wiremock::matchers::header("range", "0-999"))
        .respond_with(ResponseTemplate::new(200).set_body_json(make_rows(1000, 1)))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/v1/transactions"))
        .and(wiremock::matchers::header("range", "1000-1999"))
        .respond_with(ResponseTemplate::new(200).set_body_json(make_rows(50, 1)))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let (sum, count) = query_sum_by_category(&client, &server.uri(), "key", "transactions", "aws", 123, 0, 9999).await.unwrap();
    assert_eq!(sum, 1050);
    assert_eq!(count, 1050);
}

#[tokio::test]
async fn client_id_filter_in_query() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/v1/transactions"))
        .and(query_param("client_id", "eq.1001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let result = query_sum_by_category(&client, &server.uri(), "key", "transactions", "aws", 1001, 0, 9999).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn http_4xx_returns_err() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/v1/transactions"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let result = query_sum_by_category(&client, &server.uri(), "key", "transactions", "aws", 123, 0, 9999).await;
    assert!(result.is_err());
}

fn make_txns(n: usize) -> Vec<Transaction> {
    (0..n)
        .map(|i| Transaction {
            id: i as i64,
            client_id: 1,
            amount: i as u64 + 1,
            category: 2,
            category_name: "aws_spend".to_owned(),
            timestamp: Q1_START + i as u64,
        })
        .collect()
}

#[test]
fn compute_tx_commitment_is_deterministic() {
    let txns = make_txns(BATCH_SIZE);
    let h1 = compute_tx_commitment(&txns).unwrap();
    let h2 = compute_tx_commitment(&txns).unwrap();
    assert_eq!(fr_to_decimal(&h1), fr_to_decimal(&h2));
}

#[test]
fn compute_tx_commitment_differs_for_different_inputs() {
    let txns_a = make_txns(BATCH_SIZE);
    let txns_b = {
        let mut b = txns_a.clone();
        b[0].amount += 1;
        b
    };
    let h_a = compute_tx_commitment(&txns_a).unwrap();
    let h_b = compute_tx_commitment(&txns_b).unwrap();
    assert_ne!(fr_to_decimal(&h_a), fr_to_decimal(&h_b));
}
