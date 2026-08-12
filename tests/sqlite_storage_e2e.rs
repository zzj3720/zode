#[path = "support/http_sse.rs"]
mod http_sse_support;
pub(crate) mod support;

use std::{
    io::{Error, ErrorKind},
    path::Path,
    time::Duration,
};

use http_sse_support::*;
use reqwest::StatusCode;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use support::{
    authenticated, db_blocking, http_client, require_ulid, response_bytes, response_json,
    response_text, HttpRequestExt,
};

#[derive(Clone, Debug)]
struct SnapshotRow {
    snapshot_id: i64,
    stream_version: i64,
    payload: Vec<u8>,
}

fn read_snapshots(path: &Path) -> rusqlite::Result<Vec<SnapshotRow>> {
    let connection = Connection::open(path)?;
    connection.busy_timeout(Duration::from_secs(5))?;
    let mut statement = connection.prepare(
        "SELECT snapshot_id, stream_version, payload
         FROM snapshots ORDER BY snapshot_id ASC",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(SnapshotRow {
            snapshot_id: row.get(0)?,
            stream_version: row.get(1)?,
            payload: row.get(2)?,
        })
    })?;
    rows.collect()
}

async fn snapshots(
    path: &Path,
) -> Result<Vec<SnapshotRow>, Box<dyn std::error::Error + Send + Sync>> {
    let path = path.to_owned();
    db_blocking(move || read_snapshots(&path)).await
}

fn event_cursor(path: &Path) -> rusqlite::Result<i64> {
    let connection = Connection::open(path)?;
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.query_row(
        "SELECT COALESCE(MAX(global_position), 0) FROM events",
        [],
        |row| row.get(0),
    )
}

async fn cursor(path: &Path) -> Result<i64, Box<dyn std::error::Error + Send + Sync>> {
    let path = path.to_owned();
    db_blocking(move || event_cursor(&path)).await
}

const SQLITE_DERIVED_INDEX_NAMES: [&str; 3] = [
    "events_by_stream_version",
    "events_by_command",
    "snapshots_by_stream_version",
];
const SQLITE_CANONICAL_TRIGGER_NAMES: [&str; 9] = [
    "events_insert_dirty",
    "event_streams_insert_dirty",
    "event_streams_update_dirty",
    "event_streams_delete_dirty",
    "commands_insert_dirty",
    "commands_update_dirty",
    "commands_delete_dirty",
    "events_update_invalidates_integrity",
    "events_delete_invalidates_integrity",
];
const SQLITE_EXTRA_INDEX_NAME: &str = "e2e_extra_events";

#[derive(Debug, PartialEq, Eq)]
struct SqliteCatalogEvidence {
    event_count: i64,
    metadata_clean: bool,
    canonical_trigger_sql: Vec<(String, String)>,
    required_index_sql: Vec<(String, String)>,
}

fn read_sqlite_catalog_evidence(
    connection: &Connection,
    session_id: &str,
) -> rusqlite::Result<SqliteCatalogEvidence> {
    let event_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM events WHERE stream_id = ?1",
        params![session_id],
        |row| row.get(0),
    )?;
    let metadata_clean: bool = connection.query_row(
        "SELECT storage_schema_version = 1
                AND projection_schema_version = 1
                AND projections_dirty = 0
         FROM storage_metadata WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let mut canonical_trigger_sql = Vec::new();
    for trigger_name in SQLITE_CANONICAL_TRIGGER_NAMES {
        let sql: String = connection.query_row(
            "SELECT COALESCE(MAX(sql), '') FROM sqlite_master
             WHERE type = 'trigger' AND name = ?1",
            params![trigger_name],
            |row| row.get(0),
        )?;
        canonical_trigger_sql.push((trigger_name.to_owned(), sql));
    }
    let mut required_index_sql = Vec::new();
    for index_name in SQLITE_DERIVED_INDEX_NAMES {
        let sql: String = connection.query_row(
            "SELECT COALESCE(MAX(sql), '') FROM sqlite_master
             WHERE type = 'index' AND name = ?1",
            params![index_name],
            |row| row.get(0),
        )?;
        required_index_sql.push((index_name.to_owned(), sql));
    }
    Ok(SqliteCatalogEvidence {
        event_count,
        metadata_clean,
        canonical_trigger_sql,
        required_index_sql,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_sqlite_snapshot_cursor_follows_public_commits(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database_path = test_database("snapshot-cursor")?;
    let mut server = TestServer::start(&database_path).await?;
    let client = http_client()?;
    let response = authenticated(client.post(server.url("/v1/sessions")))
        .header("Idempotency-Key", "snapshot-cursor-create")
        .json(&json!({}))
        .send_with_timeout()
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let session_id = require_ulid(&response_json(response).await?)?;
    for (key, content) in [
        ("snapshot-cursor-first", "first"),
        ("snapshot-cursor-second", "second"),
    ] {
        let response =
            authenticated(client.post(server.url(&format!("/v1/sessions/{session_id}/messages"))))
                .header("Idempotency-Key", key)
                .json(&json!({ "content": content }))
                .send_with_timeout()
                .await?;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let _ = response_bytes(response).await?;
    }
    server.stop().await?;
    let cursor_after = cursor(&database_path).await?;
    let snapshot_rows = snapshots(&database_path).await?;
    assert!(snapshot_rows.iter().any(|row| row.stream_version == 1));
    assert!(snapshot_rows.iter().any(|row| row.stream_version == 2));
    assert!(snapshot_rows.iter().any(|row| row.stream_version == 3));
    assert!(cursor_after >= 3);
    let mut restarted = TestServer::start(&database_path).await?;
    let response = authenticated(client.get(restarted.url(&format!("/v1/sessions/{session_id}"))))
        .send_with_timeout()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await?;
    assert_eq!(body["version"], 3);
    restarted.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_legacy_state_digest_restarts_appends_and_preserves_history(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database_path = test_database("legacy-state-digest")?;
    let (mut server, client, session_id) = create_history(&database_path).await?;
    server.stop().await?;

    let database_file = database_path.path().to_owned();
    let stream_id = session_id.clone();
    db_blocking(move || {
        let connection = Connection::open(database_file)?;
        let (snapshot_id, stream_version, payload): (i64, i64, Vec<u8>) = connection.query_row(
            "SELECT snapshot_id, stream_version, payload FROM snapshots
             WHERE stream_id = ?1 ORDER BY stream_version DESC, snapshot_id DESC LIMIT 1",
            params![&stream_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let legacy_digest = Sha256::digest(&payload).to_vec();
        let snapshot_changed = connection.execute(
            "UPDATE snapshots SET state_digest_version = 1, state_digest = ?1
             WHERE snapshot_id = ?2",
            params![&legacy_digest, snapshot_id],
        )?;
        let anchor_changed = connection.execute(
            "UPDATE integrity_anchors SET state_digest_version = 1, state_digest = ?1
             WHERE stream_id = ?2 AND stream_version = ?3",
            params![&legacy_digest, &stream_id, stream_version],
        )?;
        if snapshot_changed != 1 || anchor_changed != 1 {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
        Ok(())
    })
    .await?;

    let mut restarted = TestServer::start(&database_path).await?;
    let response =
        authenticated(client.post(restarted.url(&format!("/v1/sessions/{session_id}/messages"))))
            .header("Idempotency-Key", "legacy-digest-next-message")
            .json(&json!({"content": "message after digest upgrade"}))
            .send_with_timeout()
            .await?;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let accepted = response_json(response).await?;
    assert_eq!(accepted["version"], 3);
    restarted.stop().await?;

    let mut final_restart = TestServer::start(&database_path).await?;
    let response =
        authenticated(client.get(final_restart.url(&format!("/v1/sessions/{session_id}"))))
            .send_with_timeout()
            .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let state = response_json(response).await?;
    final_restart.stop().await?;
    assert_eq!(state["version"], 3);
    assert_eq!(state["transcript"][0]["content"], "historical message");
    assert_eq!(
        state["transcript"][1]["content"],
        "message after digest upgrade"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_snapshot_cannot_override_event_stream(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database_path = test_database("snapshot-mismatch")?;
    let (mut server, client, session_id) = create_history(&database_path).await?;
    server.stop().await?;

    let snapshots = snapshots(&database_path).await?;
    let latest = snapshots
        .iter()
        .max_by_key(|row| row.snapshot_id)
        .ok_or_else(|| Error::new(ErrorKind::NotFound, "no snapshot candidate was created"))?;
    let mut state: Value = serde_json::from_slice(&latest.payload)?;
    state["transcript"] = json!([]);
    let payload = serde_json::to_vec(&state)?;
    let checksum = format!("sha256:{:x}", Sha256::digest(&payload));
    let database_file = database_path.path().to_owned();
    let snapshot_id = latest.snapshot_id;
    db_blocking(move || {
        let connection = Connection::open(database_file)?;
        connection.execute(
            "UPDATE snapshots SET payload = ?1, checksum = ?2 WHERE snapshot_id = ?3",
            params![payload, checksum, snapshot_id],
        )?;
        Ok(())
    })
    .await?;

    let mut restarted = TestServer::start(&database_path).await?;
    let response = authenticated(client.get(restarted.url(&format!("/v1/sessions/{session_id}"))))
        .send_with_timeout()
        .await?;
    let status = response.status();
    let body = response_text(response).await?;
    restarted.stop().await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "full replay should win over a semantically valid but inconsistent snapshot: {body}"
    );
    let body: Value = serde_json::from_str(&body)?;
    assert_eq!(body["version"], 2, "unexpected projection: {body}");
    assert_eq!(
        body["transcript"][0]["content"], "historical message",
        "snapshot contents overrode the event stream: {body}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_corrupt_latest_snapshot_falls_back(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database_path = test_database("snapshot-corrupt")?;
    let (mut server, client, session_id) = create_history(&database_path).await?;
    server.stop().await?;

    let snapshots = snapshots(&database_path).await?;
    let latest = snapshots
        .iter()
        .max_by_key(|row| row.snapshot_id)
        .ok_or_else(|| Error::new(ErrorKind::NotFound, "no snapshot candidate was created"))?;
    assert!(snapshots
        .iter()
        .any(|row| row.snapshot_id != latest.snapshot_id));
    let database_file = database_path.path().to_owned();
    let snapshot_id = latest.snapshot_id;
    db_blocking(move || {
        let connection = Connection::open(database_file)?;
        connection.execute(
            "UPDATE snapshots SET payload = ?1 WHERE snapshot_id = ?2",
            params![
                "corrupt payload with the wrong SQLite column type",
                snapshot_id
            ],
        )?;
        Ok(())
    })
    .await?;

    let mut restarted = TestServer::start(&database_path).await?;
    let response = authenticated(client.get(restarted.url(&format!("/v1/sessions/{session_id}"))))
        .send_with_timeout()
        .await?;
    let status = response.status();
    let body = response_text(response).await?;
    restarted.stop().await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "corrupt latest snapshot should be skipped in favor of the old snapshot: {body}"
    );
    let body: Value = serde_json::from_str(&body)?;
    assert_eq!(body["version"], 2);
    assert_eq!(body["transcript"][0]["content"], "historical message");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
// SQLite-specific backend contract: dirty projections and missing required
// indexes are repaired, while a harmless extra index remains valid.
async fn e2e_sqlite_restart_rebuilds_derived_indexes_and_allows_harmless_extra_index(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database_path = test_database("index-rebuild")?;
    let (mut server, client, session_id) = create_history_opaque(&database_path).await?;
    server.stop().await?;

    // SQLite-specific stage 1: dirty projection rows are repaired first. The
    // subsequent index-only corruption must start from a clean metadata fast path.
    let database_file = database_path.path().to_owned();
    let session_for_db = session_id.clone();
    let (event_count, remaining) = db_blocking(move || {
        let connection = Connection::open(database_file)?;
        let event_count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM events WHERE stream_id = ?1",
            params![&session_for_db],
            |row| row.get(0),
        )?;
        connection.execute(
            "DELETE FROM event_streams WHERE stream_id = ?1",
            params![&session_for_db],
        )?;
        connection.execute(
            "DELETE FROM commands WHERE stream_id = ?1",
            params![&session_for_db],
        )?;
        let remaining: i64 = connection.query_row(
            "SELECT COUNT(*) FROM events WHERE stream_id = ?1",
            params![&session_for_db],
            |row| row.get(0),
        )?;
        Ok((event_count, remaining))
    })
    .await?;
    assert_eq!(event_count, 2);
    assert_eq!(remaining, event_count);

    let mut repaired = TestServer::start(&database_path).await?;
    let get_response =
        authenticated(client.get(repaired.url(&format!("/v1/sessions/{session_id}"))))
            .send_with_timeout()
            .await?;
    let get_status = get_response.status();
    let get_body = response_text(get_response).await?;
    let retry_response =
        authenticated(client.post(repaired.url(&format!("/v1/sessions/{session_id}/messages"))))
            .header("Idempotency-Key", "message-history")
            .json(&json!({"content": "historical message"}))
            .send_with_timeout()
            .await?;
    let retry_status = retry_response.status();
    let retry_body = response_text(retry_response).await?;
    repaired.stop().await?;
    assert!(
        get_status == StatusCode::OK && retry_status == StatusCode::ACCEPTED,
        "projection repair restart failed; GET status={get_status} body={get_body}; retry status={retry_status} body={retry_body}"
    );
    let get_body: Value = serde_json::from_str(&get_body)?;
    assert_eq!(get_body["version"], 2);
    assert_eq!(get_body["transcript"][0]["content"], "historical message");
    let retry_body: Value = serde_json::from_str(&retry_body)?;
    assert_eq!(retry_body["version"], 2);

    // SQLite-specific stage 2: remove only catalog indexes while metadata stays
    // clean, then require physical sqlite_master repair after public recovery.
    let database_file = database_path.path().to_owned();
    let (metadata_clean_before, metadata_clean_after) = db_blocking(move || {
        let connection = Connection::open(database_file)?;
        let metadata_clean_before: bool = connection.query_row(
            "SELECT storage_schema_version = 1
                    AND projection_schema_version = 1
                    AND projections_dirty = 0
             FROM storage_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        if !metadata_clean_before {
            return Err(rusqlite::Error::InvalidQuery);
        }
        for index_name in SQLITE_DERIVED_INDEX_NAMES {
            let sql: String = connection.query_row(
                "SELECT sql FROM sqlite_master
                 WHERE type = 'index' AND name = ?1 AND sql IS NOT NULL",
                params![index_name],
                |row| row.get(0),
            )?;
            if sql.trim().is_empty() {
                return Err(rusqlite::Error::InvalidQuery);
            }
            connection.execute(&format!("DROP INDEX {index_name}"), [])?;
        }
        let metadata_clean_after: bool = connection.query_row(
            "SELECT storage_schema_version = 1
                    AND projection_schema_version = 1
                    AND projections_dirty = 0
             FROM storage_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        Ok((metadata_clean_before, metadata_clean_after))
    })
    .await?;
    assert!(metadata_clean_before);
    assert!(metadata_clean_after);

    let mut restarted = TestServer::start(&database_path).await?;
    let get_response =
        authenticated(client.get(restarted.url(&format!("/v1/sessions/{session_id}"))))
            .send_with_timeout()
            .await?;
    let get_status = get_response.status();
    let get_body = response_text(get_response).await?;
    let retry_response =
        authenticated(client.post(restarted.url(&format!("/v1/sessions/{session_id}/messages"))))
            .header("Idempotency-Key", "message-history")
            .json(&json!({"content": "historical message"}))
            .send_with_timeout()
            .await?;
    let retry_status = retry_response.status();
    let retry_body = response_text(retry_response).await?;
    restarted.stop().await?;
    assert!(
        get_status == StatusCode::OK && retry_status == StatusCode::ACCEPTED,
        "clean metadata/index-only restart failed; GET status={get_status} body={get_body}; retry status={retry_status} body={retry_body}"
    );
    let get_body: Value = serde_json::from_str(&get_body)?;
    assert_eq!(get_body["version"], 2);
    assert_eq!(get_body["transcript"][0]["content"], "historical message");
    let retry_body: Value = serde_json::from_str(&retry_body)?;
    assert_eq!(retry_body["version"], 2);

    let database_file = database_path.path().to_owned();
    let session_for_db = session_id.clone();
    let repaired_catalog = db_blocking(move || {
        let connection = Connection::open(database_file)?;
        read_sqlite_catalog_evidence(&connection, &session_for_db)
    })
    .await?;
    assert!(repaired_catalog.metadata_clean);
    assert!(repaired_catalog.event_count > 0);
    for (index_name, sql) in &repaired_catalog.required_index_sql {
        assert!(
            !sql.trim().is_empty(),
            "SQLite required index {index_name} was not rebuilt with SQL"
        );
    }
    for (trigger_name, sql) in &repaired_catalog.canonical_trigger_sql {
        assert!(
            !sql.trim().is_empty(),
            "SQLite canonical trigger {trigger_name} disappeared during projection repair"
        );
    }

    // SQLite-specific stage 3: a non-UNIQUE index outside the required set is
    // harmless catalog state. Preserve the clean facts, metadata, canonical
    // triggers, and required indexes while adding it to a stopped database.
    let database_file = database_path.path().to_owned();
    let session_for_db = session_id.clone();
    let (catalog_before_extra, catalog_after_extra, extra_sql) = db_blocking(move || {
        let connection = Connection::open(database_file)?;
        let catalog_before_extra = read_sqlite_catalog_evidence(&connection, &session_for_db)?;
        if !catalog_before_extra.metadata_clean || catalog_before_extra.event_count == 0 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        if catalog_before_extra
            .canonical_trigger_sql
            .iter()
            .any(|(_, sql)| sql.trim().is_empty())
            || catalog_before_extra
                .required_index_sql
                .iter()
                .any(|(_, sql)| sql.trim().is_empty())
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let existing_extra: i64 = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?1",
            params![SQLITE_EXTRA_INDEX_NAME],
            |row| row.get(0),
        )?;
        if existing_extra != 0 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        connection.execute("CREATE INDEX e2e_extra_events ON events(command_id)", [])?;
        let catalog_after_extra = read_sqlite_catalog_evidence(&connection, &session_for_db)?;
        let extra_sql: String = connection.query_row(
            "SELECT COALESCE(MAX(sql), '') FROM sqlite_master
             WHERE type = 'index' AND name = ?1",
            params![SQLITE_EXTRA_INDEX_NAME],
            |row| row.get(0),
        )?;
        if extra_sql.trim().is_empty() {
            return Err(rusqlite::Error::InvalidQuery);
        }
        Ok((catalog_before_extra, catalog_after_extra, extra_sql))
    })
    .await?;
    assert_eq!(
        catalog_before_extra, catalog_after_extra,
        "adding a harmless extra SQLite index changed facts, metadata, canonical triggers, or required indexes"
    );
    assert!(catalog_before_extra.metadata_clean);
    assert!(catalog_before_extra.event_count > 0);
    assert!(!extra_sql.trim().is_empty());

    let mut extra_index_server = match TestServer::start(&database_path).await {
        Ok(server) => server,
        Err(error) => {
            let message = error.to_string();
            if message.contains("readiness deadline expired") {
                return Err(Error::other(format!(
                    "harmless extra-index recovery was inconclusive: readiness timed out: {message}"
                ))
                .into());
            }
            if !message.contains("exited with non-zero process status") {
                return Err(Error::other(format!(
                    "harmless extra-index recovery was inconclusive: child was not proven to exit non-zero: {message}"
                ))
                .into());
            }
            if !message.contains("zode exited before readiness") {
                return Err(Error::other(format!(
                    "harmless extra-index recovery was inconclusive: child failed before a readiness EOF was observed: {message}"
                ))
                .into());
            }
            let database_file = database_path.path().to_owned();
            let session_for_db = session_id.clone();
            let (failure_catalog, failure_extra_sql) = db_blocking(move || {
                let connection = Connection::open(database_file)?;
                let catalog = read_sqlite_catalog_evidence(&connection, &session_for_db)?;
                let extra_sql: String = connection.query_row(
                    "SELECT COALESCE(MAX(sql), '') FROM sqlite_master
                     WHERE type = 'index' AND name = ?1",
                    params![SQLITE_EXTRA_INDEX_NAME],
                    |row| row.get(0),
                )?;
                Ok((catalog, extra_sql))
            })
            .await?;
            assert_eq!(failure_catalog, catalog_before_extra);
            assert_eq!(failure_extra_sql, extra_sql);
            return Err(Error::other(format!(
                "production rejected harmless extra SQLite index before readiness: {message}"
            ))
            .into());
        }
    };

    let response =
        authenticated(client.get(extra_index_server.url(&format!("/v1/sessions/{session_id}"))))
            .send_with_timeout()
            .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_response(response).await?;
    assert_eq!(body["version"], 2);
    assert_eq!(body["transcript"][0]["content"], "historical message");

    let response = authenticated(client.get(extra_index_server.url("/v1/events")))
        .send_with_timeout()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let events = read_sse_events(response, 2).await?;
    let _ = assert_two_ordered_session_events(&events, &session_id)?;

    let response = authenticated(
        client.post(extra_index_server.url(&format!("/v1/sessions/{session_id}/messages"))),
    )
    .header("Idempotency-Key", "message-history")
    .json(&json!({"content": "historical message"}))
    .send_with_timeout()
    .await?;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let replay = json_response(response).await?;
    assert_eq!(replay["version"], 2);

    extra_index_server.stop().await?;
    let database_file = database_path.path().to_owned();
    let session_for_db = session_id.clone();
    let (final_catalog, final_extra_sql) = db_blocking(move || {
        let connection = Connection::open(database_file)?;
        let catalog = read_sqlite_catalog_evidence(&connection, &session_for_db)?;
        let extra_sql: String = connection.query_row(
            "SELECT COALESCE(MAX(sql), '') FROM sqlite_master
             WHERE type = 'index' AND name = ?1",
            params![SQLITE_EXTRA_INDEX_NAME],
            |row| row.get(0),
        )?;
        Ok((catalog, extra_sql))
    })
    .await?;
    assert_eq!(final_catalog, catalog_before_extra);
    assert!(!final_extra_sql.trim().is_empty());
    Ok(())
}
