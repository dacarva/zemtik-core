use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};
use zemtik::config::AggFn;
use zemtik::db::{aggregate_table, compute_tx_commitment, fr_to_decimal, query_aggregate_table, query_sum_by_category, BATCH_SIZE, Q1_START};
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

// ---------------------------------------------------------------------------
// aggregate_table — SQLite path (new generic query function)
// ---------------------------------------------------------------------------

fn make_test_sqlite_conn() -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE transactions (
            id INTEGER PRIMARY KEY,
            client_id INTEGER NOT NULL,
            amount INTEGER,
            category_name TEXT,
            timestamp INTEGER NOT NULL
        );",
    )
    .unwrap();
    conn
}

fn insert_row(conn: &rusqlite::Connection, id: i64, client_id: i64, amount: Option<i64>, category: &str, ts: i64) {
    conn.execute(
        "INSERT INTO transactions (id, client_id, amount, category_name, timestamp) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![id, client_id, amount, category, ts],
    ).unwrap();
}

#[test]
fn aggregate_table_sum_with_category_filter() {
    let conn = make_test_sqlite_conn();
    insert_row(&conn, 1, 123, Some(100), "aws", 1000);
    insert_row(&conn, 2, 123, Some(200), "aws", 2000);
    insert_row(&conn, 3, 123, Some(50), "payroll", 1500);

    let (sum, count) = aggregate_table(
        &conn, "transactions", "amount", "timestamp",
        Some("category_name"), "aws", &AggFn::Sum, 123, 500, 9999,
    ).unwrap();
    assert_eq!(sum, 300);
    assert_eq!(count, 2);
}

#[test]
fn aggregate_table_count_no_category_filter() {
    let conn = make_test_sqlite_conn();
    insert_row(&conn, 1, 123, Some(100), "aws", 1000);
    insert_row(&conn, 2, 123, Some(200), "aws", 2000);
    insert_row(&conn, 3, 123, Some(50), "payroll", 1500);

    let (count_val, row_count) = aggregate_table(
        &conn, "transactions", "amount", "timestamp",
        None, "ignored", &AggFn::Count, 123, 500, 9999,
    ).unwrap();
    assert_eq!(count_val, 3);
    assert_eq!(row_count, 3);
}

#[test]
fn aggregate_table_count_nullable_column_differs_from_count_star() {
    let conn = make_test_sqlite_conn();
    insert_row(&conn, 1, 123, Some(100), "aws", 1000);
    insert_row(&conn, 2, 123, None, "aws", 2000); // NULL amount

    // COUNT(amount) counts non-null rows only
    let (count_val, _) = aggregate_table(
        &conn, "transactions", "amount", "timestamp",
        None, "any", &AggFn::Count, 123, 500, 9999,
    ).unwrap();
    assert_eq!(count_val, 1, "COUNT(amount) should ignore NULL rows");
}

#[test]
fn aggregate_table_sum_no_category_filter() {
    let conn = make_test_sqlite_conn();
    insert_row(&conn, 1, 123, Some(300), "aws", 1000);
    insert_row(&conn, 2, 123, Some(700), "payroll", 2000);

    let (sum, _) = aggregate_table(
        &conn, "transactions", "amount", "timestamp",
        None, "any", &AggFn::Sum, 123, 500, 9999,
    ).unwrap();
    assert_eq!(sum, 1000);
}

#[test]
fn aggregate_table_unknown_category_returns_zero() {
    let conn = make_test_sqlite_conn();
    insert_row(&conn, 1, 123, Some(100), "aws", 1000);

    let (sum, count) = aggregate_table(
        &conn, "transactions", "amount", "timestamp",
        Some("category_name"), "nonexistent", &AggFn::Sum, 123, 500, 9999,
    ).unwrap();
    assert_eq!(sum, 0);
    assert_eq!(count, 0);
}

#[test]
fn aggregate_table_category_col_none_ignores_category_value() {
    let conn = make_test_sqlite_conn();
    insert_row(&conn, 1, 123, Some(100), "aws", 1000);
    insert_row(&conn, 2, 123, Some(200), "payroll", 1500);

    // category_col=None → no WHERE on category → returns total regardless of category_value
    let (sum, _) = aggregate_table(
        &conn, "transactions", "amount", "timestamp",
        None, "this_value_is_ignored", &AggFn::Sum, 123, 500, 9999,
    ).unwrap();
    assert_eq!(sum, 300);
}

#[test]
fn aggregate_table_sum_overflow_returns_err() {
    let conn = make_test_sqlite_conn();
    // Insert two rows that together overflow i64 when summed
    insert_row(&conn, 1, 123, Some(i64::MAX), "aws", 1000);
    insert_row(&conn, 2, 123, Some(i64::MAX), "aws", 2000);

    let result = aggregate_table(
        &conn, "transactions", "amount", "timestamp",
        Some("category_name"), "aws", &AggFn::Sum, 123, 500, 9999,
    );
    assert!(result.is_err(), "SUM overflow should return Err");
}

// ---------------------------------------------------------------------------
// query_aggregate_table — Supabase/PostgREST path (wiremock)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn query_aggregate_table_sum_parse_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/v1/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([{"amount": 42000}])))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let (sum, _) = query_aggregate_table(
        &client, &server.uri(), "key", "transactions",
        "amount", "timestamp", Some("category_name"), "aws",
        &AggFn::Sum, 123, false, 0, 9999,
    ).await.unwrap();
    assert_eq!(sum, 42000);
}

#[tokio::test]
async fn query_aggregate_table_count_parse_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/v1/employees"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([{"employee_id": 5}])))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let (count_val, _) = query_aggregate_table(
        &client, &server.uri(), "key", "employees",
        "employee_id", "hire_date", None, "any",
        &AggFn::Count, 123, true, 0, 9999,
    ).await.unwrap();
    assert_eq!(count_val, 5);
}

#[tokio::test]
async fn query_aggregate_table_missing_field_returns_err() {
    // PostgREST returns a non-empty array but the expected field is absent.
    // Signing a coerced 0 would produce a false attestation — must return Err.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/v1/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([{}])))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let result = query_aggregate_table(
        &client, &server.uri(), "key", "transactions",
        "amount", "timestamp", None, "any",
        &AggFn::Sum, 123, false, 0, 9999,
    ).await;
    assert!(result.is_err(), "missing field in non-empty PostgREST response must return Err, not a silent 0");
}

#[tokio::test]
async fn query_aggregate_table_skip_client_id_filter_omits_param() {
    let server = MockServer::start().await;
    // Mount a catch-all — wiremock will match regardless of query params
    Mock::given(method("GET"))
        .and(path("/rest/v1/employees"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([{"employee_id": 10}])))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let result = query_aggregate_table(
        &client, &server.uri(), "key", "employees",
        "employee_id", "hire_date", None, "any",
        &AggFn::Count, 999, true, // skip_client_id_filter = true
        0, 9999,
    ).await;
    assert!(result.is_ok());

    // Verify the request received by the server does NOT contain client_id
    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let url_str = received[0].url.to_string();
    assert!(
        !url_str.contains("client_id"),
        "URL should not contain client_id when skip_client_id_filter=true, got: {}",
        url_str
    );
}
