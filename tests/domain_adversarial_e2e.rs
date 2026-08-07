#![allow(dead_code)]

mod support;

use std::io::{Error, ErrorKind};

use reqwest::{Client, StatusCode};
use serde_json::{json, Value};

use support::{
    authenticated_as, require_ulid, response_json, response_text, write_endpoint_config,
    ConfiguredServer, HttpRequestExt, TempDatabase, TestResult,
};

const SUBJECT: &str = "domain-adversarial-subject";
const OTHER_SUBJECT: &str = "domain-adversarial-other-subject";

async fn create_model_less(
    client: &Client,
    server: &ConfiguredServer,
    subject: &str,
    key: &str,
) -> TestResult<String> {
    let response = authenticated_as(client.post(server.url("/v1/sessions")), subject)
        .header("Idempotency-Key", key)
        .json(&json!({}))
        .send_with_timeout()
        .await?;
    let status = response.status();
    let body = response_json(response).await?;
    if status != StatusCode::CREATED {
        return Err(Error::other(format!(
            "model-less session create failed: {status} {body}"
        ))
        .into());
    }
    require_ulid(&body)
}

async fn list_page(
    client: &Client,
    server: &ConfiguredServer,
    subject: &str,
    query: &str,
) -> TestResult<(StatusCode, String, Value)> {
    let response = authenticated_as(
        client.get(server.url(&format!("/v1/sessions?{query}"))),
        subject,
    )
    .send_with_timeout()
    .await?;
    let status = response.status();
    let body = response_text(response).await?;
    let json = serde_json::from_str(&body).unwrap_or_else(|_| Value::String(body.clone()));
    Ok((status, body, json))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_session_list_keyset_is_owner_bound_and_restart_stable() -> TestResult<()> {
    let database = TempDatabase::new("domain-list-keyset")?;
    let config = write_endpoint_config(&database, Vec::new(), 1)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;

    let mut created = Vec::new();
    for (index, key) in ["list-keyset-a", "list-keyset-b", "list-keyset-c"]
        .into_iter()
        .enumerate()
    {
        created.push(create_model_less(&client, &server, SUBJECT, key).await?);
        if index > 0 {
            assert_ne!(created[index], created[index - 1]);
        }
    }

    let (status, body, first_page) = list_page(&client, &server, SUBJECT, "limit=2").await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(first_page["schema"], "zode.session-list.v1", "{body}");
    let first_items = first_page["items"]
        .as_array()
        .ok_or_else(|| Error::other(format!("first list page omitted items: {body}")))?;
    assert_eq!(first_items.len(), 2, "{body}");
    let cursor = first_page["next_cursor"]
        .as_str()
        .ok_or_else(|| Error::other(format!("first list page omitted next_cursor: {body}")))?
        .to_owned();
    assert!(!cursor.is_empty());

    let (status, body, second_before_restart) =
        list_page(&client, &server, SUBJECT, &format!("limit=2&cursor={cursor}")).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(second_before_restart["schema"], "zode.session-list.v1", "{body}");
    let second_items = second_before_restart["items"]
        .as_array()
        .ok_or_else(|| Error::other(format!("second list page omitted items: {body}")))?;
    assert_eq!(second_items.len(), 1, "{body}");
    assert!(second_before_restart["next_cursor"].is_null(), "{body}");

    let first_ids = first_items
        .iter()
        .map(|item| {
            item["session_id"]
                .as_str()
                .ok_or_else(|| Error::other("first list item omitted session_id"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let second_id = second_items[0]["session_id"]
        .as_str()
        .ok_or_else(|| Error::other("second list item omitted session_id"))?;
    assert!(!first_ids.contains(&second_id));
    assert_eq!(first_ids.len() + 1, created.len());
    assert!(created.iter().all(|id| {
        first_ids.iter().any(|first_id| first_id == id) || second_id == id
    }));

    let (cross_status, cross_body, cross_json) =
        list_page(&client, &server, OTHER_SUBJECT, &format!("limit=2&cursor={cursor}")).await?;
    assert_eq!(cross_status, StatusCode::BAD_REQUEST, "{cross_body}");
    assert_eq!(cross_json["error"]["code"], "malformed_request", "{cross_body}");
    assert!(!cross_body.contains(&created[0]));

    server.stop().await?;
    let mut restarted = ConfiguredServer::start(&database, &config).await?;
    let (status, body, second_after_restart) =
        list_page(&client, &restarted, SUBJECT, &format!("limit=2&cursor={cursor}")).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(second_after_restart, second_before_restart, "{body}");
    restarted.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_invalid_transition_rejects_without_append() -> TestResult<()> {
    let database = TempDatabase::new("domain-invalid-transition")?;
    let config = write_endpoint_config(&database, Vec::new(), 1)?;
    let mut server = ConfiguredServer::start(&database, &config).await?;
    let client = support::http_client()?;
    let session_id = create_model_less(&client, &server, SUBJECT, "invalid-transition-create").await?;

    let first = authenticated_as(
        client.post(server.url(&format!("/v1/sessions/{session_id}/messages"))),
        SUBJECT,
    )
    .header("Idempotency-Key", "invalid-transition-first")
    .json(&json!({
        "message_id": "immutable-message-id",
        "content": "the admitted message"
    }))
    .send_with_timeout()
    .await?;
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    let first_body = response_json(first).await?;
    assert_eq!(first_body["version"], 2);

    let conflict = authenticated_as(
        client.post(server.url(&format!("/v1/sessions/{session_id}/messages"))),
        SUBJECT,
    )
    .header("Idempotency-Key", "invalid-transition-conflict")
    .json(&json!({
        "message_id": "immutable-message-id",
        "content": "a conflicting message"
    }))
    .send_with_timeout()
    .await?;
    let conflict_status = conflict.status();
    let conflict_body = response_json(conflict).await?;
    assert_eq!(conflict_status, StatusCode::UNPROCESSABLE_ENTITY, "{conflict_body}");
    assert_eq!(conflict_body["error"]["code"], "invalid_request");

    let read = authenticated_as(
        client.get(server.url(&format!("/v1/sessions/{session_id}"))),
        SUBJECT,
    )
    .send_with_timeout()
    .await?;
    assert_eq!(read.status(), StatusCode::OK);
    let state = response_json(read).await?;
    assert_eq!(state["version"], 2, "invalid transition appended an event");
    assert_eq!(state["transcript"].as_array().map(Vec::len), Some(1));
    assert_eq!(state["transcript"][0]["message_id"], "immutable-message-id");
    assert_eq!(state["transcript"][0]["content"], "the admitted message");
    assert!(!state.to_string().contains("a conflicting message"));

    server.stop().await?;
    Ok(())
}
