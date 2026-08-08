#[path = "../../tests/support/process_capture.rs"]
mod process_capture;

use std::{
    cell::RefCell,
    env,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Condvar, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use process_capture::{
    ProcessCaptureSet, ProcessIncidentReplay, ProcessObservation, ProcessReplayProof,
    ProcessStopObservation,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use url::Url;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UiMode {
    Assets,
    ApiOnly,
}

impl UiMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Assets => "assets",
            Self::ApiOnly => "api_only",
        }
    }
}

const MANAGEMENT_HOST: &str = "management.ui-delivery.test";
const CALLBACK_HOST: &str = "callback.ui-delivery.test";
const MANAGEMENT_AUTHORITY: &str = MANAGEMENT_HOST;
const CALLBACK_AUTHORITY: &str = CALLBACK_HOST;
const ACCESS_AUDIENCE: &str = "zode-ui-delivery-e2e";
const ACCESS_SUBJECT: &str = "ui-delivery-human-subject";
const ACCESS_EMAIL: &str = "ui-delivery-human@example.invalid";
const ACCESS_KID: &str = "ui-delivery-access-key";
const SERVER_AUTHORITY: &str = "ui-delivery-server-authority";
const HISTORY_PATH: &str = "/endpoints/endpoint-ui/sessions/01JUIDELIVERYHISTORY";
const SSE_PATH: &str = "/v1/endpoints/endpoint-ui/sessions/01JUIDELIVERYSSE/events";
const INCIDENT_OWNER: &str =
    "e2e_server_ui_delivery_serves_access_protected_management_assets_and_isolates_callback_origin";
const INCIDENT_CASSETTE_PATH: &str = "tests/fixtures/ui_delivery/ui-delivery-first-404.v1.json";
const INCIDENT_EVIDENCE_GAP_PATH: &str =
    "tests/fixtures/ui_delivery/ui-delivery-first-404-evidence-gap.v1.json";
const CAPTURE_ENV: &str = "ZODE_CAPTURE_FIRST_OCCURRENCE";
const CALLBACK_ENDPOINT_AUTHORITY: &str = SERVER_AUTHORITY;
const CALLBACK_ENDPOINT_SECRET: &str = "ui-delivery-endpoint-control-secret";
const CALLBACK_ENDPOINT_LABEL: &str = "ui-delivery-callback-endpoint";
const CALLBACK_TOOL_NAME: &str = "callback_tool";
const CALLBACK_PROVIDER_NAME: &str = "fixture-provider";
const CALLBACK_MODEL_NAME: &str = "fixture-model";
const CALLBACK_PROVIDER_KEY: &str = "ui-delivery-provider-key";
const CALLBACK_LATER_E2E: &str =
    "e2e_callback_origin_accepts_only_real_bearer_callback_and_never_management";
const CALLBACK_LATER_RELATION: &str = "later_test_reproduction_of_gap";
const CALLBACK_LATER_CLASSIFICATION: &str =
    "CALLBACK_LIFECYCLE_NONBLOCKING_READ_BARRIER__later_test_reproduction_of_gap";
const CALLBACK_LATER_QUARANTINE_DIR: &str =
    "target/test-recordings/quarantine/callback-lifecycle-later-gap";
const UI_ASSET_PATH_CAPTURE_ENV: &str = "ZODE_CAPTURE_UI_ASSET_PATH_LATER_GAP";
const UI_ASSET_PATH_E2E: &str =
    "e2e_server_ui_delivery_hardening_rejects_asset_tree_symlink_and_path_escape_before_ready";
const UI_ASSET_PATH_RELATION: &str = "later_test_reproduction_of_gap";
const UI_ASSET_PATH_CLASSIFICATION: &str =
    "UI_ASSET_DIRECTORY_PATH_ESCAPE_REACHED_READY__later_test_reproduction_of_gap";
const UI_ASSET_PATH_FIRST_OBSERVED: &str = "relation=later_test_reproduction_of_gap; ui_assets_directory=../ui-dist; expected=pre_ready_rejection; actual=ready";
const UI_ASSET_PATH_CASSETTE: &str =
    "tests/fixtures/incidents/server-ui-assets-path-escape-later-gap.v1.json";

const ACCESS_PRIVATE_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEArXMZzRpkHwtdgWw+vPxg8LKx71TV9jIqaLp3v1vZAGOf+0U1
GZwbztbax5t0n2x+uuK2sT3FZXe6Tgx8VIG4d33VxSc/KY3Mc4H4idhj/F24asrU
q72wOZMQY7lthi2pLKdFB8j9zjg9TBvlywxZGeg2MyJ5iBAho0h4FdxCuoOe7IZh
zmuoQwIt++SDjQPNz4WiHLAEQUkomCOKEUWAtCuh+M2m6Djd8sQ0nyc1VzDad4IW
DOL00WRsgRJ0up0LBL3FFaaIYzOTtyePhaJHxnpdsCTTTe7Qy7YGXcA8jHLtz+PZ
iImAd/6sR/f10jp8lhIqegcSLT0xvHgsSln5XwIDAQABAoIBAE+hxwg35Byuopzf
XgR1GGqZmACp4du412iip4Sm/f9kPdhmQ0VBOzEgymwXDpl8/cf+e2LvWbfGmrXn
nJNNxSuzDZiI9sI0tFeZpcpfmzQLsTXybmZ03bnpL36hbMvMHd3+4735xLDPeDD/
o+Yvgp7W0j9yxfo2ccMd6+gZaldngZgwNc1TPctRbPFAPz8CQvXw42gFfiL8m1SQ
pvhKW/gOvrCjU5nhf0CvGkdWy/cWHWn+U9p6nRRa4KtpKtDiaOqiHmIFhrEB3bmY
EJhfkqLM3xy1IfL8ujFCADFz1tKb3qDLxAla1XzdQ2SoHbswrXJelQmUQSlmGwbL
x8AKopECgYEA303tGIA2pvsxRo72m0qHiX4rbk42RdDkDdcGhS8sT4rNIJbJCiPS
hl5/n3FnzAroIgmVU9goCAPhKqJY5kwEyoTrlutc57Fbtj59ROrPrFlpPxzf7q5b
OnXwwyKusI2QanSADuXrRqHrpH2UuS9nM3IqXrpZxDN1qjiwziHcs/ECgYEAxth6
Snq1gPv/TkI/BCs2CTE9Q04YflI36iHxA6IKlvaciW2slYq8AHqVMKeHmD9Wjggt
VDNOKewE9OTBGet48Ggbt4REZ/YllxH/hWOBRciCUWcdEaXc0xjCuBVN8cjKxet0
1cANrCAqiVeFq67SndxQCzgCvOv495LDb8WPkk8CgYEArVmVQXvm8WH3Mssw7gTB
ix8DIDJfN3ueTpAqY6HnSCh8bVwg3VpJyD373Q7wgRnGcwX1go0/Jlm8ppg5Yy6I
WZ8uNI6qJMMuax+/p4yRgz410eTcgjGgaJW+Pf3ilvSOs9WUw/wA1WhFwgArQEdo
Wiu6cKdBoGpCYc54ksz+xEECgYEArKDDimV9rb0YqJhanQPmpZRZ21SxbvlyEZHl
64GCMA1pWOYeLrWDAedqHhNTZJmYSzZOJAtmkH6WzwTJn/cNx6iaZ3gs6xSHDeBS
NTttv2eTu5gJZIjabWnRon7cbEwlvi3sAKX7OLO0OggBxErCDsp1s0etGNbEDisc
AK1DN4ECgYB9MzecbpjV2vpAO2N5Jlq8Uz1Hn336TWz0m/ry5pgPlsV1N4Hxnaap
iyeBodLuKel+lwNVfYDJxBot2NHNf6hnQ4eeQbNZOEQTGNpUNsln1x51q4OxcG+o
dpkxaugCqD59pJh3CzzQZJDBU3CJXckyZk2Z6PWkLKXKLDLR5JW9UA==
-----END RSA PRIVATE KEY-----"#;

const ACCESS_MODULUS: &str =
    "rXMZzRpkHwtdgWw-vPxg8LKx71TV9jIqaLp3v1vZAGOf-0U1GZwbztbax5t0n2x-uuK2sT3FZXe6Tgx8VIG4d33VxSc_KY3Mc4H4idhj_F24asrUq72wOZMQY7lthi2pLKdFB8j9zjg9TBvlywxZGeg2MyJ5iBAho0h4FdxCuoOe7IZhzmuoQwIt--SDjQPNz4WiHLAEQUkomCOKEUWAtCuh-M2m6Djd8sQ0nyc1VzDad4IWDOL00WRsgRJ0up0LBL3FFaaIYzOTtyePhaJHxnpdsCTTTe7Qy7YGXcA8jHLtz-PZiImAd_6sR_f10jp8lhIqegcSLT0xvHgsSln5Xw";

#[test]
fn e2e_server_ui_delivery_serves_access_protected_management_assets_and_isolates_callback_origin(
) -> TestResult {
    // Keep the historical diagnostic artifact independently validated, but use
    // the authoritative public GET / exchange for this post-bootstrap capture.
    let _legacy_cassette = read_incident_cassette()?;
    let jwks = JwksFixture::start()?;
    let temp = tempfile::tempdir()?;
    let ui_dist = build_test_owned_ui_dist(temp.path())?;
    let config_path = write_server_config(temp.path(), &jwks, UiMode::Assets, Some("ui-dist"))?;
    assert_ui_mode_config(&config_path, UiMode::Assets, Some(&ui_dist))?;
    let unrelated_cwd = temp.path().join("unrelated-working-directory");
    fs::create_dir_all(&unrelated_cwd)?;
    let mut server = ServerProcess::start_in_directory(&config_path, &unrelated_cwd)?;
    let mut first_post_bootstrap = FirstPostBootstrapRecorder::new()?;
    let expected_index = fs::read(ui_dist.join("index.html"))?;
    let expected_asset_hrefs = extract_versioned_asset_hrefs(&expected_index);
    let mut expected_assets = Vec::new();
    for asset_href in &expected_asset_hrefs {
        let path = asset_path_in_tree(&ui_dist, asset_href)
            .ok_or_else(|| io::Error::other(format!("invalid built asset path {asset_href}")))?;
        expected_assets.push((asset_href.clone(), fs::read(path)?));
    }
    fs::remove_dir_all(&ui_dist)?;
    fs::create_dir_all(&ui_dist)?;
    fs::write(
        ui_dist.join("index.html"),
        b"<!doctype html><html><body>modified before first request</body></html>",
    )?;
    let edge = AccessEdge::start(&server.base_url)?;
    let assertion = access_assertion(&jwks.issuer())?;
    let mut failures = Vec::new();
    let mut callback_asset_probe_path = "/assets/ui-delivery-missing-asset-probe.js".to_owned();
    let response_markers = vec![
        assertion.clone(),
        ACCESS_SUBJECT.to_owned(),
        ACCESS_EMAIL.to_owned(),
    ];
    let root = management_request_with_first_post_bootstrap_recording(
        &edge,
        &jwks,
        HttpRequestSpec {
            method: "GET",
            path: "/",
            host: MANAGEMENT_HOST,
            accept: "text/html",
            assertion: Some(&assertion),
            extra_headers: &[],
            body: &[],
        },
        &mut first_post_bootstrap,
    )?;
    let shallow_root_404 = root.status == 404;
    if shallow_root_404 {
        failures.push(
            "BLOCKED_SHALLOW_404: management root is still HTTP 404; no static shell, history fallback, or asset behavior is evidence"
                .to_owned(),
        );
        first_post_bootstrap.record_observation(
            &root,
            &expected_index,
            &expected_asset_hrefs,
            &response_markers,
        )?;
    } else {
        check_html_response("management root", &root, &mut failures);
        scan_response("management root", &root, &response_markers, &mut failures);
        check_no_cookie("management root", &root, &mut failures);

        let root_asset_hrefs = extract_versioned_asset_hrefs(&root.body);
        if root_asset_hrefs.is_empty() {
            failures.push(
                "management root did not contain parseable versioned asset href/src values"
                    .to_owned(),
            );
        }
        if root.body != expected_index || root_asset_hrefs != expected_asset_hrefs {
            failures.push(
                "management root did not serve the exact in-memory HTML and asset set loaded before READY"
                    .to_owned(),
            );
        }
        first_post_bootstrap.record_observation(
            &root,
            &expected_index,
            &expected_asset_hrefs,
            &response_markers,
        )?;

        let history = management_request(
            &edge,
            "GET",
            HISTORY_PATH,
            "text/html",
            Some(&assertion),
            &[],
        )?;
        check_html_response(
            "management canonical history route",
            &history,
            &mut failures,
        );
        if root.body != history.body {
            failures.push(
                "canonical browser history route did not return the same application shell as /"
                    .to_owned(),
            );
        }
        let history_asset_hrefs = extract_versioned_asset_hrefs(&history.body);
        if root_asset_hrefs != history_asset_hrefs {
            failures.push(
                "management root and canonical history route referenced different versioned asset sets"
                    .to_owned(),
            );
        }
        if history.body != expected_index || history_asset_hrefs != expected_asset_hrefs {
            failures.push(
                "management history did not serve the exact in-memory HTML and asset set loaded before READY"
                    .to_owned(),
            );
        }
        scan_response(
            "management canonical history route",
            &history,
            &response_markers,
            &mut failures,
        );
        check_no_cookie(
            "management canonical history route",
            &history,
            &mut failures,
        );

        let mut initial_assets = Vec::new();
        for asset_href in &root_asset_hrefs {
            if callback_asset_probe_path.starts_with("/assets/ui-delivery-missing") {
                callback_asset_probe_path = asset_href.clone();
            }
            let asset = management_request(&edge, "GET", asset_href, "*/*", Some(&assertion), &[])?;
            check_asset_response(
                &format!("management versioned asset {asset_href}"),
                &asset,
                &mut failures,
            );
            scan_response(
                &format!("management versioned asset {asset_href}"),
                &asset,
                &response_markers,
                &mut failures,
            );
            check_no_cookie(
                &format!("management versioned asset {asset_href}"),
                &asset,
                &mut failures,
            );
            let expected_body = expected_assets
                .iter()
                .find(|(expected_href, _)| expected_href == asset_href)
                .map(|(_, expected_body)| expected_body);
            if expected_body != Some(&asset.body) {
                failures.push(format!(
                    "management versioned asset {asset_href} did not serve the exact in-memory bytes loaded before READY"
                ));
            }
            initial_assets.push((asset_href.clone(), asset));
        }

        fs::remove_dir_all(&ui_dist)?;
        fs::create_dir_all(&ui_dist)?;
        fs::write(
            ui_dist.join("index.html"),
            b"<!doctype html><html><body>modified after READY</body></html>",
        )?;
        let stable_root =
            management_request(&edge, "GET", "/", "text/html", Some(&assertion), &[])?;
        assert_response_unchanged(
            "management root after asset-tree deletion and modification",
            &root,
            &stable_root,
            &mut failures,
        );
        let stable_history = management_request(
            &edge,
            "GET",
            HISTORY_PATH,
            "text/html",
            Some(&assertion),
            &[],
        )?;
        assert_response_unchanged(
            "management history after asset-tree deletion and modification",
            &history,
            &stable_history,
            &mut failures,
        );
        for (asset_href, initial_asset) in &initial_assets {
            let stable_asset =
                management_request(&edge, "GET", asset_href, "*/*", Some(&assertion), &[])?;
            assert_response_unchanged(
                &format!(
                    "management asset {asset_href} after asset-tree deletion and modification"
                ),
                initial_asset,
                &stable_asset,
                &mut failures,
            );
        }
    }

    let system = management_request(
        &edge,
        "GET",
        "/v1/system",
        "application/json",
        Some(&assertion),
        &[],
    )?;
    check_system_response("management system API", &system, &mut failures);
    check_no_store("management system API", &system, &mut failures);
    scan_response(
        "management system API",
        &system,
        &response_markers,
        &mut failures,
    );
    check_no_cookie("management system API", &system, &mut failures);

    let sse = management_request(
        &edge,
        "GET",
        SSE_PATH,
        "text/event-stream",
        Some(&assertion),
        &[],
    )?;
    if sse.status != 404 {
        failures.push(format!(
            "management SSE route returned HTTP {}, expected a typed 404 for the unknown Endpoint/session",
            sse.status
        ));
    }
    check_not_html("management SSE route", &sse, &mut failures);
    check_no_store("management SSE route", &sse, &mut failures);
    scan_response(
        "management SSE route",
        &sse,
        &response_markers,
        &mut failures,
    );
    check_no_cookie("management SSE route", &sse, &mut failures);

    let missing_server_assertion = origin_request(
        &server.base_url,
        "GET",
        "/",
        MANAGEMENT_HOST,
        "text/html",
        None,
        &[],
    )?;
    if missing_server_assertion.status != 401 {
        failures.push(format!(
            "direct management origin without Cf-Access-Jwt-Assertion returned HTTP {}, expected 401",
            missing_server_assertion.status
        ));
    }
    check_not_html(
        "direct unauthenticated management origin",
        &missing_server_assertion,
        &mut failures,
    );
    check_no_store(
        "direct unauthenticated management origin",
        &missing_server_assertion,
        &mut failures,
    );
    check_no_cookie(
        "direct unauthenticated management origin",
        &missing_server_assertion,
        &mut failures,
    );

    let edge_missing_assertion = management_request(&edge, "GET", "/", "text/html", None, &[])?;
    if edge_missing_assertion.status != 401 {
        failures.push(format!(
            "Access edge admitted a management request without an assertion (HTTP {})",
            edge_missing_assertion.status
        ));
    }
    check_not_html(
        "Access edge missing assertion",
        &edge_missing_assertion,
        &mut failures,
    );
    check_no_cookie(
        "Access edge missing assertion",
        &edge_missing_assertion,
        &mut failures,
    );

    for (label, path) in [
        ("callback root", "/"),
        (
            "callback versioned asset",
            callback_asset_probe_path.as_str(),
        ),
        ("callback browser history route", HISTORY_PATH),
        ("callback management API", "/v1/system"),
    ] {
        let response = callback_request(&edge, "GET", path, "text/html", &[])?;
        check_safe_callback_404_surface(label, &response, &response, &mut failures);
        scan_response(label, &response, &response_markers, &mut failures);

        let access_response = origin_request_with_headers(
            &edge.callback_url(),
            HttpRequestSpec {
                method: "GET",
                path,
                host: CALLBACK_AUTHORITY,
                accept: "text/html",
                assertion: Some(&assertion),
                extra_headers: &[],
                body: &[],
            },
        )?;
        check_safe_callback_404_surface(
            &format!("{label} with valid Access"),
            &access_response,
            &response,
            &mut failures,
        );
        scan_response(
            &format!("{label} with valid Access"),
            &access_response,
            &response_markers,
            &mut failures,
        );
    }

    let forwarded_surface_baseline =
        callback_request(&edge, "GET", "/v1/system", "application/json", &[])?;
    check_safe_callback_404_surface(
        "callback Forwarded/X-Forwarded-Host baseline",
        &forwarded_surface_baseline,
        &forwarded_surface_baseline,
        &mut failures,
    );
    let forwarded_surface_probe = origin_request_with_headers(
        &edge.callback_url(),
        HttpRequestSpec {
            method: "GET",
            path: "/v1/system",
            host: CALLBACK_AUTHORITY,
            accept: "application/json",
            assertion: Some(&assertion),
            extra_headers: &[
                ("Forwarded", "host=management.ui-delivery.test"),
                ("X-Forwarded-Host", MANAGEMENT_AUTHORITY),
            ],
            body: &[],
        },
    )?;
    check_safe_callback_404_surface(
        "callback Forwarded/X-Forwarded-Host surface probe",
        &forwarded_surface_probe,
        &forwarded_surface_baseline,
        &mut failures,
    );

    if jwks.exchange_snapshot()?.is_empty() {
        failures.push(
            "valid management request never crossed the configured Access JWKS fixture".to_owned(),
        );
    }
    if !first_post_bootstrap.captured() {
        failures.push(
            "first post-bootstrap public management exchange was not durably recorded".to_owned(),
        );
    }

    drop(edge);
    let capture = server.stop()?;
    scan_server_artifacts(&capture, temp.path(), &mut failures, &response_markers)?;

    if failures.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(failures.join("; ")).into())
    }
}

#[test]
fn e2e_server_ui_delivery_hardening_rejects_invalid_ui_mode_combinations_before_ready() -> TestResult
{
    let jwks = JwksFixture::start()?;
    for (label, mode, directory) in [
        ("assets without ui_assets_directory", UiMode::Assets, None),
        (
            "api_only with ui_assets_directory",
            UiMode::ApiOnly,
            Some("ui-dist"),
        ),
    ] {
        let temp = tempfile::tempdir()?;
        let config_path = write_server_config(temp.path(), &jwks, mode, directory)?;
        assert_server_rejected_before_ready(&config_path, label)?;
    }

    let temp = tempfile::tempdir()?;
    let config_path = write_server_config(temp.path(), &jwks, UiMode::Assets, Some("ui-dist"))?;
    let mut config: Value = serde_json::from_slice(&fs::read(&config_path)?)?;
    config
        .as_object_mut()
        .ok_or_else(|| io::Error::other("test server config was not an object"))?
        .remove("ui_mode");
    fs::write(&config_path, serde_json::to_vec_pretty(&config)?)?;
    assert_server_rejected_before_ready(&config_path, "omitted ui_mode")
}

#[cfg(unix)]
#[test]
fn e2e_server_ui_delivery_hardening_rejects_asset_tree_symlink_and_path_escape_before_ready(
) -> TestResult {
    let cassette = Path::new(env!("CARGO_MANIFEST_DIR")).join(UI_ASSET_PATH_CASSETTE);
    if env::var(UI_ASSET_PATH_CAPTURE_ENV).ok().as_deref() == Some("1") {
        if cassette.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "UI asset path later-gap cassette is immutable",
            )
            .into());
        }
        return capture_ui_asset_path_escape_later_gap(&cassette);
    }
    assert_ui_asset_path_cassette_identity(&cassette)?;

    let jwks = JwksFixture::start()?;
    let temp = tempfile::tempdir()?;
    let ui_dist = build_test_owned_ui_dist(temp.path())?;

    let escape_root = temp.path().join("config-path-escape");
    fs::create_dir_all(&escape_root)?;
    let escape_config =
        write_server_config(&escape_root, &jwks, UiMode::Assets, Some("../ui-dist"))?;
    assert_server_rejected_before_ready(&escape_config, "asset directory path escape")?;

    let symlink_root = temp.path().join("config-symlink");
    fs::create_dir_all(&symlink_root)?;
    std::os::unix::fs::symlink(&ui_dist, symlink_root.join("ui-link"))?;
    let symlink_config =
        write_server_config(&symlink_root, &jwks, UiMode::Assets, Some("ui-link"))?;
    assert_server_rejected_before_ready(&symlink_config, "symlinked asset directory")
}

fn ui_asset_path_replay_config() -> TestResult<Vec<u8>> {
    Ok(serde_json::to_vec(&json!({
        "schema": "zode.server-ui-assets-path-gap-replay.v1",
        "e2e": UI_ASSET_PATH_E2E,
        "relation": UI_ASSET_PATH_RELATION,
        "entry": "real zode-server --config with an escaping ui_assets_directory",
        "ui_assets_directory": "../ui-dist",
        "expected_after_fix": {
            "ready": false,
            "phase": "config"
        }
    }))?)
}

fn ui_asset_path_quarantine() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/test-recordings/quarantine/server-ui-assets-path-later-gap")
}

fn assert_ui_asset_path_cassette_identity(cassette: &Path) -> TestResult {
    let replay = ProcessIncidentReplay::load(cassette, UI_ASSET_PATH_E2E, &[])?;
    let config: Value = serde_json::from_slice(replay.config_bytes())?;
    if replay.config_label() != "ui-assets-directory-parent-escape"
        || replay.classification() != UI_ASSET_PATH_CLASSIFICATION
        || replay.first_observed() != UI_ASSET_PATH_FIRST_OBSERVED
        || replay.config_bytes() != ui_asset_path_replay_config()?
        || config["schema"] != "zode.server-ui-assets-path-gap-replay.v1"
        || config["e2e"] != UI_ASSET_PATH_E2E
        || config["relation"] != UI_ASSET_PATH_RELATION
        || config["ui_assets_directory"] != "../ui-dist"
        || config["expected_after_fix"]["ready"] != false
    {
        return Err(io::Error::other(
            "UI asset path later-gap cassette changed identity or relation",
        )
        .into());
    }
    Ok(())
}

thread_local! {
    static CALLBACK_LATER_CAPTURE: RefCell<Option<Arc<Mutex<CallbackLaterCapture>>>> =
        const { RefCell::new(None) };
}

struct CallbackHttpRecord {
    boundary: String,
    file: String,
    sha256: String,
}

struct CallbackLaterCapture {
    root: PathBuf,
    recording_id: String,
    http_directory: PathBuf,
    http_records: Vec<CallbackHttpRecord>,
    process_capture: ProcessCaptureSet,
    process_capture_error: Option<String>,
}

impl CallbackLaterCapture {
    fn new() -> TestResult<Self> {
        let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .ok_or_else(|| io::Error::other("server manifest has no repository parent"))?;
        let quarantine_root = repository_root.join(CALLBACK_LATER_QUARANTINE_DIR);
        fs::create_dir_all(&quarantine_root)?;
        set_permissions(&quarantine_root, 0o700)?;
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let recording_id = format!("callback-lifecycle-later-{}-{nonce}", std::process::id());
        let root = quarantine_root.join(&recording_id);
        fs::create_dir(&root)?;
        set_permissions(&root, 0o700)?;
        let http_directory = root.join("http");
        fs::create_dir(&http_directory)?;
        set_permissions(&http_directory, 0o700)?;
        let mut process_capture = ProcessCaptureSet::new(
            root.join("process"),
            CALLBACK_LATER_E2E,
            &[CALLBACK_ENDPOINT_SECRET, CALLBACK_PROVIDER_KEY],
        )?;
        process_capture.capture_config(
            "callback-lifecycle-later-reproduction",
            &serde_json::to_vec(&json!({
                "schema": "zode.callback-lifecycle-gap-replay.v1",
                "e2e": CALLBACK_LATER_E2E,
                "relation": CALLBACK_LATER_RELATION,
                "entry": "real zode-server + real zode Endpoint + callback HTTP/SSE boundary",
                "known_fixture_seam": "accepted_stream_blocking_read_barrier"
            }))?,
        )?;
        sync_directory(&root)?;
        sync_directory(&quarantine_root)?;
        Ok(Self {
            root,
            recording_id,
            http_directory,
            http_records: Vec::new(),
            process_capture,
            process_capture_error: None,
        })
    }

    fn record_http(&mut self, boundary: &str, exchange: &RawHttpExchange) -> TestResult<()> {
        let sequence = self.http_records.len();
        let file = format!("http-{sequence:04}.raw.json");
        let path = self.http_directory.join(&file);
        let envelope = raw_exchange_envelope_with_boundary(
            &self.recording_id,
            CALLBACK_LATER_E2E,
            boundary,
            "later test reproduction; raw exchange retained before classification",
            exchange,
        );
        write_restricted_new_json(&path, &envelope)?;
        let sha256 = sha256_hex(&fs::read(&path)?)?;
        self.http_records.push(CallbackHttpRecord {
            boundary: boundary.to_owned(),
            file,
            sha256,
        });
        sync_directory(&self.http_directory)?;
        Ok(())
    }

    fn record_jwks(&mut self, exchanges: &[JwksExchange]) -> TestResult<()> {
        for exchange in exchanges {
            let response = exchange.response_wire.clone().unwrap_or_default();
            let response_chunks = if response.is_empty() {
                Vec::new()
            } else {
                vec![RawResponseChunk {
                    offset_us: 0,
                    bytes: response.clone(),
                }]
            };
            let raw = terminal_raw_exchange(
                &exchange.request,
                &response,
                &response_chunks,
                Instant::now(),
                0,
                None,
                if exchange.response_write_succeeded {
                    TransportTermination::Complete
                } else {
                    TransportTermination::Disconnect
                },
            );
            self.record_http("access-jwks", &raw)?;
        }
        Ok(())
    }

    fn record_process(&mut self, name: &str, capture: &ServerCapture) {
        let observation = ProcessObservation {
            name: name.to_owned(),
            stdout: capture.stdout.clone(),
            stderr: capture.stderr.clone(),
            exit_code: capture.status.code(),
            signal: ui_asset_exit_signal(&capture.status).map(|signal| signal.to_string()),
            termination: "test_stop_after_callback_lifecycle_observation".to_owned(),
            stop: Some(ProcessStopObservation {
                observed_pids: vec![capture.pid],
                reaped_pids: vec![capture.pid],
                leaked_pids: Vec::new(),
                timed_out: false,
                flush_status: "ok".to_owned(),
                proof: true,
            }),
        };
        if let Err(error) = self.process_capture.capture_process(observation) {
            self.process_capture_error = Some(error.to_string());
        }
    }

    fn finalize(&mut self, classification: &str, first_observed: &str) -> TestResult<PathBuf> {
        if let Some(error) = self.process_capture_error.take() {
            return Err(io::Error::other(format!(
                "callback process capture failed closed: {error}"
            ))
            .into());
        }
        if self.http_records.is_empty() {
            return Err(io::Error::other(
                "callback later capture contained no durable HTTP exchange",
            )
            .into());
        }
        let process_path = self
            .process_capture
            .flush(classification.to_owned(), first_observed.to_owned())?;
        let process_sha256 = sha256_hex(&fs::read(&process_path)?)?;
        let manifest = json!({
            "schema": "zode.callback-lifecycle-later-capture.v1",
            "version": 1,
            "recording_id": self.recording_id,
            "e2e_name": CALLBACK_LATER_E2E,
            "relation": CALLBACK_LATER_RELATION,
            "classification": classification,
            "first_observed": first_observed,
            "http": {
                "directory": "http",
                "records": self.http_records.iter().map(|record| json!({
                    "boundary": record.boundary,
                    "file": record.file,
                    "sha256": record.sha256,
                })).collect::<Vec<_>>()
            },
            "process_capture": {
                "path": process_path.to_string_lossy(),
                "sha256": process_sha256,
            },
            "historical_gap": "callback-lifecycle-access-edge-wouldblock-first-gap.v1.json",
            "do_not_relabel_later_capture": true,
        });
        let manifest_path = self.root.join("later-reproduction.v1.json");
        write_restricted_new_json(&manifest_path, &manifest)?;
        sync_directory(&self.root)?;
        let parent = self
            .root
            .parent()
            .ok_or_else(|| io::Error::other("callback capture root has no parent"))?;
        sync_directory(parent)?;
        Ok(manifest_path)
    }
}

fn with_callback_later_capture<T>(
    capture: Arc<Mutex<CallbackLaterCapture>>,
    run: impl FnOnce() -> T,
) -> T {
    CALLBACK_LATER_CAPTURE.with(|slot| {
        let previous = slot.replace(Some(capture));
        let result = run();
        slot.replace(previous);
        result
    })
}

fn record_active_callback_http(boundary: &str, exchange: &RawHttpExchange) -> TestResult<()> {
    CALLBACK_LATER_CAPTURE.with(|slot| {
        let Some(capture) = slot.borrow().as_ref().cloned() else {
            return Ok(());
        };
        let result = capture
            .lock()
            .map_err(|_| io::Error::other("callback later capture mutex poisoned"))?
            .record_http(boundary, exchange);
        result
    })
}

fn record_active_callback_jwks(exchanges: &[JwksExchange]) -> TestResult<()> {
    CALLBACK_LATER_CAPTURE.with(|slot| {
        let Some(capture) = slot.borrow().as_ref().cloned() else {
            return Ok(());
        };
        let result = capture
            .lock()
            .map_err(|_| io::Error::other("callback later capture mutex poisoned"))?
            .record_jwks(exchanges);
        result
    })
}

fn record_active_callback_process(name: &str, capture: &ServerCapture) {
    CALLBACK_LATER_CAPTURE.with(|slot| {
        let Some(active) = slot.borrow().as_ref().cloned() else {
            return;
        };
        if let Ok(mut capture_set) = active.lock() {
            capture_set.record_process(name, capture);
        };
    });
}

fn is_nonblocking_read_barrier(error: &(dyn std::error::Error + 'static)) -> bool {
    let text = error.to_string().to_ascii_lowercase();
    text.contains("wouldblock")
        || text.contains("resource temporarily unavailable")
        || text.contains("os error 35")
        || text.contains("operation would block")
}

fn capture_ui_asset_path_escape_later_gap(cassette: &Path) -> TestResult {
    let descriptor = ui_asset_path_replay_config()?;
    let mut capture = ProcessCaptureSet::new(ui_asset_path_quarantine(), UI_ASSET_PATH_E2E, &[])?;
    capture.capture_config("ui-assets-directory-parent-escape", &descriptor)?;
    let first = observe_ui_asset_path_escape()?;
    capture.capture_process(first.process_observation())?;
    let classification = if first.ready {
        UI_ASSET_PATH_CLASSIFICATION
    } else {
        "HARNESS_UI_ASSET_PATH_DID_NOT_REPRODUCE_READY__later_test_reproduction_of_gap"
    };
    let first_observed = if first.ready {
        UI_ASSET_PATH_FIRST_OBSERVED
    } else {
        "relation=later_test_reproduction_of_gap; ui_assets_directory=../ui-dist; target_ready_red_not_observed"
    };
    let raw = capture.flush(classification, first_observed)?;
    if !first.ready {
        return Err(io::Error::other(format!(
            "UI asset path later reproduction stopped before the typed READY red; raw={}",
            raw.display()
        ))
        .into());
    }

    let replay = ProcessIncidentReplay::load(&raw, UI_ASSET_PATH_E2E, &[])?;
    if replay.config_bytes() != descriptor
        || replay.classification() != UI_ASSET_PATH_CLASSIFICATION
        || replay.first_observed() != UI_ASSET_PATH_FIRST_OBSERVED
    {
        return Err(io::Error::other("UI asset path retained source did not reload safely").into());
    }
    let repeated = observe_ui_asset_path_escape()?;
    if !repeated.ready {
        return Err(io::Error::other(
            "same-entry UI asset path replay did not reproduce the typed READY red",
        )
        .into());
    }
    let fingerprint = format!(
        "{:x}",
        Sha256::digest(
            format!(
                "{}\0{}\0same-public-entry-ready-red-reproduced",
                replay.classification(),
                replay.first_observed()
            )
            .as_bytes()
        )
    );
    capture.promote_immutable(
        cassette,
        &ProcessReplayProof {
            matched: true,
            fingerprint,
            source_digest: replay.source_digest().to_owned(),
        },
    )?;
    Err(io::Error::other(format!(
        "UI asset path escape later reproduction retained before repair; relation={UI_ASSET_PATH_RELATION}; raw={}; cassette={}",
        raw.display(),
        cassette.display()
    ))
    .into())
}

struct UiAssetPathObservation {
    ready: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    status: ExitStatus,
    pid: u32,
    killed_by_test: bool,
}

impl UiAssetPathObservation {
    fn process_observation(&self) -> ProcessObservation {
        ProcessObservation {
            name: "zode-server".to_owned(),
            stdout: self.stdout.clone(),
            stderr: self.stderr.clone(),
            exit_code: self.status.code(),
            signal: ui_asset_exit_signal(&self.status).map(|signal| signal.to_string()),
            termination: if self.killed_by_test {
                "test_stop_after_ready_observation"
            } else {
                "process_exit_before_ready"
            }
            .to_owned(),
            stop: Some(ProcessStopObservation {
                observed_pids: vec![self.pid],
                reaped_pids: vec![self.pid],
                leaked_pids: Vec::new(),
                timed_out: false,
                flush_status: "ok".to_owned(),
                proof: true,
            }),
        }
    }
}

fn observe_ui_asset_path_escape() -> TestResult<UiAssetPathObservation> {
    let jwks = JwksFixture::start()?;
    let temp = tempfile::tempdir()?;
    let _ui_dist = build_test_owned_ui_dist(temp.path())?;
    let config_root = temp.path().join("config-path-escape");
    fs::create_dir_all(&config_root)?;
    let config_path = write_server_config(&config_root, &jwks, UiMode::Assets, Some("../ui-dist"))?;
    let stdout_path = temp.path().join("server.stdout");
    let stderr_path = temp.path().join("server.stderr");
    let stdout = private_ui_asset_log(&stdout_path)?;
    let stderr = private_ui_asset_log(&stderr_path)?;
    let binary = env::var_os("CARGO_BIN_EXE_zode-server")
        .or_else(|| env::var_os("CARGO_BIN_EXE_zode_server"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "zode-server binary missing"))?;
    let mut child = Command::new(binary)
        .current_dir(&config_root)
        .arg("--config")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()?;
    let pid = child.id();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut ready = false;
    let mut killed_by_test = false;
    loop {
        if fs::read(&stdout_path)?
            .windows(b"ZODE_SERVER_READY ".len())
            .any(|window| window == b"ZODE_SERVER_READY ")
        {
            ready = true;
            child.kill()?;
            killed_by_test = true;
            break;
        }
        if child.try_wait()?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill()?;
            killed_by_test = true;
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let status = child.wait()?;
    File::open(&stdout_path)?.sync_all()?;
    File::open(&stderr_path)?.sync_all()?;
    let stdout = read_ui_asset_log(&stdout_path)?;
    let stderr = read_ui_asset_log(&stderr_path)?;
    Ok(UiAssetPathObservation {
        ready,
        stdout,
        stderr,
        status,
        pid,
        killed_by_test,
    })
}

fn private_ui_asset_log(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn read_ui_asset_log(path: &Path) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take((4 * 1024 * 1024 + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(io::Error::other("UI asset startup output exceeded its bound").into());
    }
    Ok(bytes)
}

#[cfg(unix)]
fn ui_asset_exit_signal(status: &ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

#[cfg(not(unix))]
fn ui_asset_exit_signal(_status: &ExitStatus) -> Option<i32> {
    None
}

#[test]
fn e2e_server_ui_delivery_hardening_rejects_unbounded_asset_tree_before_ready() -> TestResult {
    let jwks = JwksFixture::start()?;
    let temp = tempfile::tempdir()?;
    let ui_dist = build_test_owned_ui_dist(temp.path())?;
    fs::write(
        ui_dist.join("oversized-unreferenced-asset.bin"),
        vec![0_u8; 8 * 1024 * 1024],
    )?;
    let config_path = write_server_config(temp.path(), &jwks, UiMode::Assets, Some("ui-dist"))?;
    assert_server_rejected_before_ready(&config_path, "unbounded asset tree")
}

#[test]
fn e2e_callback_origin_accepts_only_real_bearer_callback_and_never_management() -> TestResult {
    let capture = Arc::new(Mutex::new(CallbackLaterCapture::new()?));
    let result = with_callback_later_capture(Arc::clone(&capture), callback_lifecycle_body);
    let mut capture = capture
        .lock()
        .map_err(|_| io::Error::other("callback later capture mutex poisoned"))?;
    let classification = if let Some(error) = result.as_ref().err() {
        let text = error.to_string().to_ascii_lowercase();
        if is_nonblocking_read_barrier(error.as_ref()) {
            CALLBACK_LATER_CLASSIFICATION.to_owned()
        } else if text.contains("did not accept the real callback bearer")
            || text.contains("callback bearer")
        {
            "CALLBACK_BEARER_REJECTED__later_test_reproduction_of_gap".to_owned()
        } else {
            "CALLBACK_LIFECYCLE_UNCLASSIFIED__later_test_reproduction_of_gap".to_owned()
        }
    } else {
        "CALLBACK_LIFECYCLE_COMPLETED__later_test_reproduction_of_gap".to_owned()
    };
    let first_observed = result.as_ref().err().map_or_else(
        || {
            format!(
                "relation={CALLBACK_LATER_RELATION}; callback bearer reached Server→Endpoint durable SSE"
            )
        },
        |error| {
            format!(
                "relation={CALLBACK_LATER_RELATION}; callback lifecycle later reproduction error classified as {}",
                if is_nonblocking_read_barrier(error.as_ref()) {
                    "known_nonblocking_accepted_stream_read_barrier"
                } else if error
                    .to_string()
                    .to_ascii_lowercase()
                    .contains("callback bearer")
                {
                    "callback_bearer_rejected_by_management_proxy"
                } else {
                    "unclassified"
                }
            )
        },
    );
    let flushed = capture.finalize(&classification, &first_observed);
    match (result, flushed) {
        (Ok(()), Ok(path)) => {
            eprintln!("callback later reproduction flushed: {}", path.display());
            Ok(())
        }
        (Err(error), Ok(path)) => Err(io::Error::other(format!(
            "{error}; callback later reproduction relation={CALLBACK_LATER_RELATION} flushed={}",
            path.display()
        ))
        .into()),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(flush_error)) => Err(io::Error::other(format!(
            "callback lifecycle red: {error}; capture flush failed: {flush_error}"
        ))
        .into()),
    }
}

fn callback_lifecycle_body() -> TestResult {
    let jwks = JwksFixture::start()?;
    let boundary = CallbackBoundaryFixture::start()?;
    let temp = tempfile::tempdir()?;
    let config_path = write_server_config(temp.path(), &jwks, UiMode::ApiOnly, None)?;
    assert_ui_mode_config(&config_path, UiMode::ApiOnly, None)?;
    let server = ServerProcess::start(&config_path)?;
    let edge = AccessEdge::start(&server.base_url)?;
    let assertion = access_assertion(&jwks.issuer())?;
    for path in ["/", HISTORY_PATH] {
        let response = management_request(&edge, "GET", path, "text/html", Some(&assertion), &[])?;
        if response.status != 404 {
            return Err(io::Error::other(format!(
                "api_only management UI route {path} returned HTTP {}, expected 404",
                response.status
            ))
            .into());
        }
        let mut failures = Vec::new();
        check_not_html(
            &format!("api_only management UI route {path}"),
            &response,
            &mut failures,
        );
        if !failures.is_empty() {
            return Err(io::Error::other(failures.join("; ")).into());
        }
    }
    let endpoint_root = temp.path().join("endpoint");
    let endpoint_config =
        write_callback_endpoint_config(&endpoint_root, &boundary, &edge.callback_url())?;
    let endpoint = ServerProcess::start_endpoint(&endpoint_config)?;
    let forbidden = vec![
        assertion.clone(),
        CALLBACK_ENDPOINT_SECRET.to_owned(),
        CALLBACK_PROVIDER_KEY.to_owned(),
    ];

    let system = management_request(
        &edge,
        "GET",
        "/v1/system",
        "application/json",
        Some(&assertion),
        &[],
    )?;
    let mut system_failures = Vec::new();
    check_system_response("callback scenario system", &system, &mut system_failures);
    if !system_failures.is_empty() {
        return Err(io::Error::other(system_failures.join("; ")).into());
    }

    let endpoint_create_body = json!({
        "label": CALLBACK_ENDPOINT_LABEL,
        "base_url": endpoint.base_url,
        "control_auth": {
            "kind": "bearer",
            "secret": CALLBACK_ENDPOINT_SECRET
        }
    });
    let endpoint_create = origin_request_with_headers(
        &edge.management_url(),
        HttpRequestSpec {
            method: "POST",
            path: "/v1/endpoints",
            host: MANAGEMENT_AUTHORITY,
            accept: "application/json",
            assertion: Some(&assertion),
            extra_headers: &[
                ("Content-Type", "application/json"),
                ("Idempotency-Key", "ui-delivery-callback-endpoint-create"),
            ],
            body: &serde_json::to_vec(&endpoint_create_body)?,
        },
    )?;
    if endpoint_create.status == 404 {
        return Err(io::Error::other(
            "BLOCKED_SHALLOW_404: real Server Endpoint catalog route is not bootstrapped; callback behavior was not exercised",
        )
        .into());
    }
    if endpoint_create.status != 201 {
        return Err(io::Error::other(format!(
            "real Server Endpoint bootstrap returned HTTP {}; callback behavior was not exercised",
            endpoint_create.status
        ))
        .into());
    }
    let mut bootstrap_failures = Vec::new();
    scan_response(
        "callback Endpoint create",
        &endpoint_create,
        &forbidden,
        &mut bootstrap_failures,
    );
    if !bootstrap_failures.is_empty() {
        return Err(io::Error::other(bootstrap_failures.join("; ")).into());
    }
    let endpoint_value: Value = serde_json::from_slice(&endpoint_create.body)?;
    let endpoint_id = endpoint_value["endpoint_id"]
        .as_str()
        .ok_or_else(|| io::Error::other("callback Endpoint create omitted endpoint_id"))?
        .to_owned();

    let descriptor = origin_request_with_headers(
        &edge.management_url(),
        HttpRequestSpec {
            method: "PUT",
            path: &format!("/v1/providers/{CALLBACK_PROVIDER_NAME}"),
            host: MANAGEMENT_AUTHORITY,
            accept: "application/json",
            assertion: Some(&assertion),
            extra_headers: &[
                ("Content-Type", "application/json"),
                ("Idempotency-Key", "ui-delivery-callback-provider"),
            ],
            body: &serde_json::to_vec(&json!({
                "kind": "openai_compatible",
                "base_url": boundary.provider_base_url(),
                "models": [CALLBACK_MODEL_NAME],
                "options": {}
            }))?,
        },
    )?;
    if descriptor.status == 404 {
        return Err(io::Error::other(
            "BLOCKED_SHALLOW_404: real Server provider route is not bootstrapped; callback behavior was not exercised",
        )
        .into());
    }
    if !descriptor.status.to_string().starts_with('2') {
        return Err(io::Error::other(format!(
            "real Server provider bootstrap returned HTTP {}; callback behavior was not exercised",
            descriptor.status
        ))
        .into());
    }
    let descriptor_value: Value = serde_json::from_slice(&descriptor.body)?;
    let descriptor_revision = descriptor_value["revision"]
        .as_u64()
        .ok_or_else(|| io::Error::other("provider descriptor omitted revision"))?;

    let profile = origin_request_with_headers(
        &edge.management_url(),
        HttpRequestSpec {
            method: "POST",
            path: &format!("/v1/providers/{CALLBACK_PROVIDER_NAME}/auth-profiles"),
            host: MANAGEMENT_AUTHORITY,
            accept: "application/json",
            assertion: Some(&assertion),
            extra_headers: &[
                ("Content-Type", "application/json"),
                ("Idempotency-Key", "ui-delivery-callback-profile"),
            ],
            body: &serde_json::to_vec(&json!({
                "kind": "api_key",
                "label": "ui-delivery callback profile",
                "api_key": "ui-delivery-provider-key",
                "make_default": true,
                "sharing": {"mode": "selected", "endpoint_ids": [endpoint_id]}
            }))?,
        },
    )?;
    if profile.status == 404 {
        return Err(io::Error::other(
            "BLOCKED_SHALLOW_404: real Server provider profile route is not bootstrapped; callback behavior was not exercised",
        )
        .into());
    }
    if profile.status != 201 {
        return Err(io::Error::other(format!(
            "real Server provider profile bootstrap returned HTTP {}; callback behavior was not exercised",
            profile.status
        ))
        .into());
    }
    let profile_value: Value = serde_json::from_slice(&profile.body)?;
    let profile_id = profile_value["auth_profile_id"]
        .as_str()
        .ok_or_else(|| io::Error::other("provider profile omitted auth_profile_id"))?
        .to_owned();
    let profile_revision = profile_value["revision"]
        .as_u64()
        .ok_or_else(|| io::Error::other("provider profile omitted revision"))?;

    let session_create_path = format!("/v1/endpoints/{endpoint_id}/sessions");
    let session_create = origin_request_with_headers(
        &edge.management_url(),
        HttpRequestSpec {
            method: "POST",
            path: &session_create_path,
            host: MANAGEMENT_AUTHORITY,
            accept: "application/json",
            assertion: Some(&assertion),
            extra_headers: &[
                ("Content-Type", "application/json"),
                ("Idempotency-Key", "ui-delivery-callback-session"),
            ],
            body: &serde_json::to_vec(&json!({
                "model": {
                    "provider": CALLBACK_PROVIDER_NAME,
                    "model": CALLBACK_MODEL_NAME,
                    "provider_execution": {
                        "schema": "zode.provider-execution.v1",
                        "revision": descriptor_revision,
                        "kind": "openai_compatible",
                        "base_url": boundary.provider_base_url(),
                        "options": {}
                    },
                    "auth_profile_id": profile_id,
                    "minimum_auth_revision": profile_revision
                },
                "tools": [CALLBACK_TOOL_NAME]
            }))?,
        },
    )?;
    if session_create.status == 404 {
        return Err(io::Error::other(
            "BLOCKED_SHALLOW_404: real Server Endpoint session route is not bootstrapped; callback URL/bearer and durable SSE were not fabricated",
        )
        .into());
    }
    if session_create.status != 201 {
        return Err(io::Error::other(format!(
            "real Server session create returned HTTP {}; callback URL/bearer was not observed",
            session_create.status
        ))
        .into());
    }
    let session_value: Value = serde_json::from_slice(&session_create.body)?;
    let session_id = session_value["session_id"]
        .as_str()
        .ok_or_else(|| io::Error::other("real Server session create omitted session_id"))?;
    run_real_callback_exchange(&edge, &assertion, &endpoint_id, session_id, &boundary)
}

fn run_real_callback_exchange(
    edge: &AccessEdge,
    assertion: &str,
    endpoint_id: &str,
    session_id: &str,
    boundary: &CallbackBoundaryFixture,
) -> TestResult {
    let events_path = format!("/v1/endpoints/{endpoint_id}/sessions/{session_id}/events");
    let sse = open_sse_connection(
        &edge.management_url(),
        &events_path,
        MANAGEMENT_AUTHORITY,
        assertion,
    )
    .map_err(|error| io::Error::other(format!("open_sse_connection: {error}")))?;
    let message_path = format!("/v1/endpoints/{endpoint_id}/sessions/{session_id}/messages");
    let message = origin_request_with_headers(
        &edge.management_url(),
        HttpRequestSpec {
            method: "POST",
            path: &message_path,
            host: MANAGEMENT_AUTHORITY,
            accept: "application/json",
            assertion: Some(assertion),
            extra_headers: &[
                ("Content-Type", "application/json"),
                ("Idempotency-Key", "ui-delivery-callback-message"),
            ],
            body: br#"{"content":"start callback"}"#,
        },
    )
    .map_err(|error| io::Error::other(format!("callback message request: {error}")))?;
    if message.status != 202 {
        let _ = boundary.release();
        return Err(io::Error::other(format!(
            "real Server session message returned HTTP {}; callback URL/bearer was not observed",
            message.status
        ))
        .into());
    }

    let invocation = boundary
        .wait_for_invocation()
        .map_err(|error| io::Error::other(format!("callback invocation barrier: {error}")))?;
    let callback_url = find_value_string(&invocation.body, "callback_url").ok_or_else(|| {
        io::Error::other(
            "real external tool invocation omitted callback_url; this is a behavior mismatch, not a first-occurrence replay",
        )
    })?;
    let parsed_callback = Url::parse(&callback_url)?;
    if parsed_callback.host_str() != Some(CALLBACK_AUTHORITY) {
        return Err(io::Error::other(
            "real external tool callback URL did not use the configured callback authority",
        )
        .into());
    }
    let callback_path = parsed_callback.path().to_owned();
    if !callback_path.starts_with(&format!("/v1/endpoints/{endpoint_id}/callbacks/")) {
        return Err(
            io::Error::other("real external tool callback URL was not Endpoint-scoped").into(),
        );
    }
    let bearer = invocation
        .authorization
        .as_deref()
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            io::Error::other(
                "real external tool invocation omitted its callback bearer; this is a behavior mismatch, not a first-occurrence replay",
            )
        })?
        .to_owned();

    for path in [
        "/",
        "/v1/system",
        &format!("/endpoints/{endpoint_id}/sessions/{session_id}"),
    ] {
        let baseline = origin_request(
            &edge.callback_url(),
            "GET",
            path,
            CALLBACK_AUTHORITY,
            "text/html",
            None,
            &[],
        )?;
        let mut failures = Vec::new();
        check_safe_callback_404_surface(
            &format!("callback unauthenticated route {path}"),
            &baseline,
            &baseline,
            &mut failures,
        );
        let response = origin_request_with_headers(
            &edge.callback_url(),
            HttpRequestSpec {
                method: "GET",
                path,
                host: CALLBACK_AUTHORITY,
                accept: "text/html",
                assertion: Some(assertion),
                extra_headers: &[],
                body: &[],
            },
        )?;
        check_safe_callback_404_surface(
            &format!("callback valid-Access route {path}"),
            &response,
            &baseline,
            &mut failures,
        );
        if !failures.is_empty() {
            return Err(io::Error::other(failures.join("; ")).into());
        }
    }

    let forwarded_baseline = origin_request(
        &edge.callback_url(),
        "GET",
        "/v1/system",
        CALLBACK_AUTHORITY,
        "application/json",
        None,
        &[],
    )?;
    let mut forwarded_failures = Vec::new();
    check_safe_callback_404_surface(
        "callback Forwarded/X-Forwarded-Host lifecycle baseline",
        &forwarded_baseline,
        &forwarded_baseline,
        &mut forwarded_failures,
    );
    let forwarded_api = origin_request_with_headers(
        &edge.callback_url(),
        HttpRequestSpec {
            method: "GET",
            path: "/v1/system",
            host: CALLBACK_AUTHORITY,
            accept: "application/json",
            assertion: Some(assertion),
            extra_headers: &[
                ("Forwarded", "host=management.ui-delivery.test"),
                ("X-Forwarded-Host", MANAGEMENT_AUTHORITY),
            ],
            body: &[],
        },
    )?;
    check_safe_callback_404_surface(
        "callback Forwarded/X-Forwarded-Host lifecycle probe",
        &forwarded_api,
        &forwarded_baseline,
        &mut forwarded_failures,
    );
    if !forwarded_failures.is_empty() {
        return Err(io::Error::other(forwarded_failures.join("; ")).into());
    }
    let management_callback = origin_request_with_headers(
        &edge.management_url(),
        HttpRequestSpec {
            method: "POST",
            path: &callback_path,
            host: MANAGEMENT_AUTHORITY,
            accept: "application/json",
            assertion: Some(assertion),
            extra_headers: &[
                ("Authorization", format!("Bearer {bearer}").as_str()),
                ("Forwarded", "host=callback.ui-delivery.test"),
                ("X-Forwarded-Host", CALLBACK_AUTHORITY),
                ("Content-Type", "application/json"),
            ],
            body: br#"{"status":"completed","result":{"content":"callback terminal"}}"#,
        },
    )?;
    if (200..300).contains(&management_callback.status) {
        return Err(
            io::Error::other("management origin accepted the callback bearer route").into(),
        );
    }

    let callback = origin_request_with_headers(
        &edge.callback_url(),
        HttpRequestSpec {
            method: "POST",
            path: &callback_path,
            host: CALLBACK_AUTHORITY,
            accept: "application/json",
            assertion: None,
            extra_headers: &[
                ("Authorization", format!("Bearer {bearer}").as_str()),
                ("Content-Type", "application/json"),
            ],
            body: br#"{"status":"completed","result":{"content":"callback terminal"}}"#,
        },
    )?;
    if !(200..300).contains(&callback.status) {
        return Err(io::Error::other(format!(
            "callback origin did not accept the real callback bearer (HTTP {})",
            callback.status
        ))
        .into());
    }
    boundary.release()?;
    let events = sse.read_until_terminal()?;
    if !events
        .windows(b"completed".len())
        .any(|window| window == b"completed")
    {
        return Err(io::Error::other(
            "Endpoint durable SSE did not prove the callback tool reached terminal completed state",
        )
        .into());
    }
    Ok(())
}

fn find_value_string(value: &Value, key: &str) -> Option<String> {
    match value {
        Value::Object(object) => {
            if let Some(string) = object.get(key).and_then(Value::as_str) {
                return Some(string.to_owned());
            }
            object
                .values()
                .find_map(|value| find_value_string(value, key))
        }
        Value::Array(values) => values
            .iter()
            .find_map(|value| find_value_string(value, key)),
        _ => None,
    }
}

#[test]
#[ignore = "explicit first-occurrence capture; never part of the default suite"]
fn record_ui_delivery_first_occurrence() -> TestResult {
    if env::var(CAPTURE_ENV).ok().as_deref() != Some("1") {
        return Err(
            io::Error::other(format!("first-occurrence capture requires {CAPTURE_ENV}=1")).into(),
        );
    }
    let evidence_gap = read_incident_evidence_gap()?;
    if !ignored_raw_contains_recording(&evidence_gap["recording_id"])? {
        return Err(io::Error::other(
            "FIRST_OCCURRENCE_EVIDENCE_GAP: the ignored raw exchange is missing; this capture cannot promote or relabel a later occurrence as first",
        )
        .into());
    }

    let destination = incident_cassette_path();
    if destination.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "first-occurrence cassette already exists and will not be overwritten",
        )
        .into());
    }

    let jwks = JwksFixture::start()?;
    let temp = tempfile::tempdir()?;
    let _ui_dist = build_test_owned_ui_dist(temp.path())?;
    let config_path = write_server_config(temp.path(), &jwks, UiMode::Assets, Some("ui-dist"))?;
    let mut server = ServerProcess::start(&config_path)?;
    let edge = AccessEdge::start(&server.base_url)?;
    let assertion = access_assertion(&jwks.issuer())?;
    let raw = raw_request(
        &edge.management_url(),
        "GET",
        "/",
        MANAGEMENT_HOST,
        "text/html",
        Some(&assertion),
        &[],
    )?;
    let raw_capture_parent = temp.path().join("quarantine");
    fs::create_dir_all(&raw_capture_parent)?;
    set_permissions(&raw_capture_parent, 0o700)?;
    let raw_capture_root = raw_capture_parent.join("ui-delivery-management-root-first-404");
    fs::create_dir(&raw_capture_root)?;
    set_permissions(&raw_capture_root, 0o700)?;
    let raw_capture_path = raw_capture_root.join("000001.raw.json");
    let raw_capture = raw_exchange_envelope(
        "ui-delivery-management-root-first-404",
        INCIDENT_OWNER,
        "retain the historical diagnostic exchange before parsing; this artifact is not the post-bootstrap capture",
        &raw,
    );
    write_restricted_new_json(&raw_capture_path, &raw_capture)?;
    sync_directory(&raw_capture_root)?;
    sync_directory(&raw_capture_parent)?;
    let response = parse_http_response(&raw.response)?;
    if !has_header(&raw.request, "Cf-Access-Jwt-Assertion")
        || !String::from_utf8_lossy(&raw.request).contains("GET / HTTP/1.1")
    {
        return Err(io::Error::other(
            "captured first occurrence did not retain the expected public request",
        )
        .into());
    }
    if response.status != 404 {
        return Err(io::Error::other(format!(
            "capture requires the unfixed first management UI response to be HTTP 404, got {}",
            response.status
        ))
        .into());
    }

    let request = json!({
        "method": "GET",
        "authority": MANAGEMENT_HOST,
        "path": "/",
        "headers": {
            "Accept": "text/html",
            "Cf-Access-Jwt-Assertion": "SLOT_ACCESS_ASSERTION"
        },
        "body": ""
    });
    let response_body = String::from_utf8(response.body).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "first management UI response was not UTF-8",
        )
    })?;
    let mut cassette = json!({
        "schema": "zode.http-incident-recording.v1",
        "version": 1,
        "recording_id": "ui-delivery-management-root-first-404",
        "owner": INCIDENT_OWNER,
        "boundary": "management_http",
        "first_failure": {
            "status": 404,
            "error_code": "missing_management_ui_route",
            "body": response_body
        },
        "slots": ["SLOT_ACCESS_ASSERTION"],
        "request": request,
        "response": {
            "status": 404,
            "headers": {},
            "body": response_body
        },
        "canonical_fingerprint": {
            "algorithm": "sha256",
            "request": "",
            "response": ""
        },
        "whole_digest": ""
    });
    let request_digest = sha256_hex(&serde_json::to_vec(&cassette["request"])?)?;
    let response_digest = sha256_hex(&serde_json::to_vec(&cassette["response"])?)?;
    cassette["canonical_fingerprint"]["request"] = Value::String(request_digest);
    cassette["canonical_fingerprint"]["response"] = Value::String(response_digest);
    let envelope_digest = sha256_hex(&serde_json::to_vec(&cassette)?)?;
    cassette["whole_digest"] = Value::String(format!("sha256:{envelope_digest}"));
    validate_incident_cassette(&cassette)?;

    let quarantine = temp.path().join("quarantine/ui-delivery-first-404.json");
    write_new_json(&quarantine, &cassette, 0o600)?;
    let bytes = fs::read(&quarantine)?;
    scan_secret_free(&bytes, &[&assertion, ACCESS_SUBJECT, ACCESS_EMAIL])?;
    promote_immutable_cassette(&quarantine, &destination)?;
    drop(edge);
    let _ = server.stop()?;
    Ok(())
}

fn incident_cassette_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(INCIDENT_CASSETTE_PATH)
}

fn read_incident_cassette() -> TestResult<Value> {
    let path = incident_cassette_path();
    let bytes = fs::read(path)?;
    scan_secret_free(&bytes, &[ACCESS_PRIVATE_KEY])?;
    let cassette: Value = serde_json::from_slice(&bytes)?;
    validate_incident_cassette(&cassette)?;
    Ok(cassette)
}

fn read_incident_evidence_gap() -> TestResult<Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(INCIDENT_EVIDENCE_GAP_PATH);
    let bytes = fs::read(path)?;
    scan_secret_free(&bytes, &[ACCESS_PRIVATE_KEY])?;
    let evidence_gap: Value = serde_json::from_slice(&bytes)?;
    validate_incident_evidence_gap(&evidence_gap)?;
    Ok(evidence_gap)
}

fn validate_incident_evidence_gap(evidence_gap: &Value) -> TestResult {
    let object = evidence_gap
        .as_object()
        .ok_or_else(|| io::Error::other("UI delivery evidence-gap record is not an object"))?;
    let required = [
        "schema",
        "version",
        "recording_id",
        "owner",
        "boundary",
        "evidence_status",
        "cassette_is_freezing",
        "raw_status",
        "raw_search_root",
        "raw_search_marker",
        "cassette",
        "reason",
        "do_not_relabel_later_capture",
        "whole_digest",
    ];
    if object.len() != required.len() || required.iter().any(|key| !object.contains_key(*key)) {
        return Err(io::Error::other("UI delivery evidence-gap fields were changed").into());
    }
    if evidence_gap["schema"] != "zode.http-incident-evidence.v1"
        || evidence_gap["version"] != 1
        || evidence_gap["recording_id"] != "ui-delivery-management-root-first-404"
        || evidence_gap["owner"] != INCIDENT_OWNER
        || evidence_gap["boundary"] != "management_http"
        || evidence_gap["evidence_status"] != "non_freezing_diagnostic"
        || evidence_gap["cassette_is_freezing"] != false
        || evidence_gap["raw_status"] != "missing"
        || evidence_gap["raw_search_root"] != "target/test-recordings/quarantine"
        || evidence_gap["raw_search_marker"] != "ui-delivery-management-root-first-404"
        || evidence_gap["cassette"] != INCIDENT_CASSETTE_PATH
        || evidence_gap["do_not_relabel_later_capture"] != true
    {
        return Err(io::Error::other("UI delivery evidence-gap metadata was changed").into());
    }
    let reason = evidence_gap["reason"]
        .as_str()
        .ok_or_else(|| io::Error::other("UI delivery evidence-gap reason was removed"))?;
    if reason != "The original capture used a temporary quarantine that was deleted with its test directory; no ignored raw exchange remains." {
        return Err(io::Error::other("UI delivery evidence-gap reason was changed").into());
    }

    let mut without_digest = evidence_gap.clone();
    without_digest["whole_digest"] = Value::String(String::new());
    let expected = format!(
        "sha256:{}",
        sha256_hex(&serde_json::to_vec(&without_digest)?)?
    );
    if evidence_gap["whole_digest"] != expected {
        return Err(io::Error::other("UI delivery evidence-gap digest was not recomputed").into());
    }
    Ok(())
}

fn ignored_raw_contains_recording(evidence_gap_recording_id: &Value) -> TestResult<bool> {
    let marker = evidence_gap_recording_id
        .as_str()
        .ok_or_else(|| io::Error::other("UI delivery evidence-gap recording id was malformed"))?;
    let relative_root = "target/test-recordings/quarantine";
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut roots = Vec::new();
    if let Some(root) = env::var_os("ZODE_TEST_RECORDINGS_ROOT") {
        roots.push(PathBuf::from(root));
    }
    roots.push(manifest.join(relative_root));
    if let Some(parent) = manifest.parent() {
        roots.push(parent.join(relative_root));
    }
    for root in roots {
        if raw_tree_contains_marker(&root, marker)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn raw_tree_contains_marker(root: &Path, marker: &str) -> io::Result<bool> {
    if !root.exists() {
        return Ok(false);
    }
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            if raw_tree_contains_marker(&path, marker)? {
                return Ok(true);
            }
        } else if path.is_file() {
            let bytes = fs::read(path)?;
            if bytes
                .windows(marker.len())
                .any(|window| window == marker.as_bytes())
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn validate_incident_cassette(cassette: &Value) -> TestResult {
    let object = cassette
        .as_object()
        .ok_or_else(|| io::Error::other("UI delivery incident cassette is not an object"))?;
    let required = [
        "schema",
        "version",
        "recording_id",
        "owner",
        "boundary",
        "first_failure",
        "slots",
        "request",
        "response",
        "canonical_fingerprint",
        "whole_digest",
    ];
    if object.len() != required.len() || required.iter().any(|key| !object.contains_key(*key)) {
        return Err(io::Error::other("UI delivery incident cassette fields were changed").into());
    }
    if cassette["schema"] != "zode.http-incident-recording.v1"
        || cassette["version"] != 1
        || cassette["recording_id"] != "ui-delivery-management-root-first-404"
        || cassette["owner"] != INCIDENT_OWNER
        || cassette["boundary"] != "management_http"
        || cassette["slots"] != json!(["SLOT_ACCESS_ASSERTION"])
    {
        return Err(io::Error::other("UI delivery incident cassette metadata was changed").into());
    }
    if cassette["first_failure"]["status"] != 404
        || cassette["first_failure"]["error_code"] != "missing_management_ui_route"
        || cassette["response"]["status"] != 404
        || cassette["response"]["headers"] != json!({})
        || cassette["request"]
            != json!({
                "method": "GET",
                "authority": MANAGEMENT_HOST,
                "path": "/",
                "headers": {
                    "Accept": "text/html",
                    "Cf-Access-Jwt-Assertion": "SLOT_ACCESS_ASSERTION"
                },
                "body": ""
            })
    {
        return Err(io::Error::other("UI delivery incident cassette exchange was changed").into());
    }
    for field in [
        cassette["first_failure"]["body"].as_str(),
        cassette["response"]["body"].as_str(),
    ] {
        if field.is_none()
            || field != Some(cassette["response"]["body"].as_str().unwrap_or_default())
        {
            return Err(io::Error::other("UI delivery incident cassette body was changed").into());
        }
    }
    let request_fingerprint = cassette["canonical_fingerprint"]["request"]
        .as_str()
        .unwrap_or_default();
    let response_fingerprint = cassette["canonical_fingerprint"]["response"]
        .as_str()
        .unwrap_or_default();
    if cassette["canonical_fingerprint"]["algorithm"] != "sha256"
        || request_fingerprint.len() != 64
        || response_fingerprint.len() != 64
        || request_fingerprint != "5db19c72e9c4f78161b123c30c35a2576f99840f3cdf275474d9daaa7f66f48e"
        || response_fingerprint
            != "e645c92e50a7dbb77350d157f8ffad2bd4b89ad1b853fa7be4a53a6096c0f455"
        || !request_fingerprint
            .chars()
            .all(|character| character.is_ascii_hexdigit())
        || !response_fingerprint
            .chars()
            .all(|character| character.is_ascii_hexdigit())
        || cassette["whole_digest"]
            != "sha256:e4815e4348684ce4938e8925436c925e78eff3e4c702c0df0be1ab390398b3b2"
    {
        return Err(
            io::Error::other("UI delivery incident cassette fingerprints were changed").into(),
        );
    }
    Ok(())
}

fn assert_ui_mode_config(
    config_path: &Path,
    expected_mode: UiMode,
    expected_directory: Option<&Path>,
) -> TestResult {
    let config: Value = serde_json::from_slice(&fs::read(config_path)?)?;
    if config["ui_mode"] != expected_mode.as_str() {
        return Err(io::Error::other(format!(
            "test config did not explicitly select ui_mode={}",
            expected_mode.as_str()
        ))
        .into());
    }
    match expected_directory {
        Some(expected) => {
            let configured = config["ui_assets_directory"].as_str().ok_or_else(|| {
                io::Error::other("assets mode omitted ui_assets_directory in test config")
            })?;
            let configured_path = Path::new(configured);
            let resolved = if configured_path.is_absolute() {
                configured_path.to_owned()
            } else {
                config_path
                    .parent()
                    .ok_or_else(|| io::Error::other("server config has no parent directory"))?
                    .join(configured_path)
            };
            if resolved != expected {
                return Err(io::Error::other(format!(
                    "assets directory was not resolved relative to the server config: expected {}, got {}",
                    expected.display(),
                    resolved.display()
                ))
                .into());
            }
        }
        None if config.get("ui_assets_directory").is_some() => {
            return Err(io::Error::other(
                "api_only test config unexpectedly included ui_assets_directory",
            )
            .into());
        }
        None => {}
    }
    Ok(())
}

fn assert_server_rejected_before_ready(config_path: &Path, label: &str) -> TestResult {
    match ServerProcess::start(config_path) {
        Ok(mut server) => {
            let _ = server.stop()?;
            Err(io::Error::other(format!("{label} unexpectedly emitted READY")).into())
        }
        Err(error) if error.to_string().contains("readiness timeout") => Ok(()),
        Err(error) => Err(io::Error::other(format!(
            "{label} did not reach the expected pre-READY rejection barrier: {error}"
        ))
        .into()),
    }
}

fn write_server_config(
    root: &Path,
    jwks: &JwksFixture,
    ui_mode: UiMode,
    ui_assets_directory: Option<&str>,
) -> TestResult<PathBuf> {
    let secret_directory = root.join("secrets");
    fs::create_dir_all(&secret_directory)?;
    set_permissions(&secret_directory, 0o700)?;
    let subject_key_file = root.join("subject.key");
    fs::write(&subject_key_file, [0x5a_u8; 32])?;
    set_permissions(&subject_key_file, 0o600)?;
    let mut config = json!({
        "schema": "zode.server-config.v1",
        "listen": "127.0.0.1:0",
        "management_origin": format!("https://{MANAGEMENT_AUTHORITY}"),
        "callback_origin": format!("https://{CALLBACK_AUTHORITY}"),
        "server_authority_id": SERVER_AUTHORITY,
        "deployment": "server_only",
        "ui_mode": ui_mode.as_str(),
        "control_database": root.join("control.sqlite"),
        "secret_directory": secret_directory,
        "access": {
            "issuer": jwks.issuer(),
            "audiences": [ACCESS_AUDIENCE],
            "jwks_url": jwks.jwks_url(),
            "subject_key_file": subject_key_file,
            "subject_key_version": 1
        }
    });
    if let Some(directory) = ui_assets_directory {
        config["ui_assets_directory"] = Value::String(directory.to_owned());
    }
    let path = root.join("server.json");
    fs::write(&path, serde_json::to_vec_pretty(&config)?)?;
    Ok(path)
}

fn build_test_owned_ui_dist(root: &Path) -> TestResult<PathBuf> {
    let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| io::Error::other("server manifest has no repository parent"))?;
    let web_root = repository_root.join("web");
    let dist = root.join("ui-dist");
    let output = Command::new("vp")
        .current_dir(&web_root)
        .args(["build", "--outDir"])
        .arg(&dist)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "STATIC_UI_BUILD_BLOCKED: vp build failed with status {}",
            output.status
        ))
        .into());
    }
    let index = fs::read(dist.join("index.html"))?;
    let assets = extract_versioned_asset_hrefs(&index);
    if assets.is_empty() {
        return Err(io::Error::other(
            "STATIC_UI_BUILD_BLOCKED: test-owned dist/index.html omitted a hashed asset",
        )
        .into());
    }
    for asset in assets {
        let path = asset_path_in_tree(&dist, &asset).ok_or_else(|| {
            io::Error::other(format!(
                "STATIC_UI_BUILD_BLOCKED: test-owned dist asset href is unsafe: {asset}"
            ))
        })?;
        if !path.is_file() {
            return Err(io::Error::other(format!(
                "STATIC_UI_BUILD_BLOCKED: test-owned dist omitted referenced asset {asset}"
            ))
            .into());
        }
    }
    Ok(dist)
}

fn asset_path_in_tree(root: &Path, asset_href: &str) -> Option<PathBuf> {
    let file_name = asset_href.strip_prefix("/assets/")?;
    if !is_versioned_asset_path(asset_href) || file_name.contains('/') {
        return None;
    }
    Some(root.join("assets").join(file_name))
}

fn endpoint_binary() -> TestResult<PathBuf> {
    let path = env::var_os("ZODE_ENDPOINT_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join("target/debug/zode")
        });
    if !path.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "real zode Endpoint binary missing; set ZODE_ENDPOINT_BIN",
        )
        .into());
    }
    Ok(path)
}

fn write_callback_endpoint_config(
    root: &Path,
    fixture: &CallbackBoundaryFixture,
    callback_origin: &str,
) -> TestResult<PathBuf> {
    fs::create_dir_all(root.join("credentials"))?;
    fs::create_dir_all(root.join("blobs"))?;
    let controller_secret = root.join("controller.secret");
    fs::write(&controller_secret, CALLBACK_ENDPOINT_SECRET)?;
    set_permissions(&controller_secret, 0o600)?;
    let config = json!({
        "schema": "zode.config.v1",
        "listen": "127.0.0.1:0",
        "runtime_store": {"kind": "sqlite", "path": root.join("endpoint.sqlite")},
        "credential_replica_store": {"kind": "files", "directory": "credentials"},
        "blob_store": {"kind": "files", "directory": "blobs"},
        "controller_auth": [{
            "authority_id": CALLBACK_ENDPOINT_AUTHORITY,
            "revision": 1,
            "kind": "bearer_secret_file",
            "secret_file": "controller.secret"
        }],
        "runtime": {
            "tool_foreground_ms": 100,
            "max_rounds_per_activation": 8,
            "model_step_max_attempts": 1,
            "model_retry_base_ms": 1,
            "model_retry_max_ms": 10,
            "snapshot_every_events": 1
        },
        "provider_execution": {
            "adapter_kinds": ["openai_compatible"],
            "allowed_base_url_origins": [fixture.base_url()]
        },
        "callback": {"allowed_public_origins": [callback_origin]},
        "tools": [{
            "name": CALLBACK_TOOL_NAME,
            "description": "controlled callback fixture",
            "input_schema": {"type": "object"},
            "completion_mode": "external_callback",
            "auto_wait_timeout_seconds": 20,
            "recovery": {
                "on_running_restart": "await_callback",
                "retry_dispatch": "never"
            },
            "adapter": {"kind": "http", "url": fixture.tool_url()}
        }]
    });
    let path = root.join("endpoint.json");
    fs::write(&path, serde_json::to_vec_pretty(&config)?)?;
    Ok(path)
}

fn access_assertion(issuer: &str) -> TestResult<String> {
    let now = unix_seconds();
    let mut claims = Map::new();
    claims.insert("iss".to_owned(), Value::String(issuer.to_owned()));
    claims.insert("aud".to_owned(), json!([ACCESS_AUDIENCE]));
    claims.insert("sub".to_owned(), Value::String(ACCESS_SUBJECT.to_owned()));
    claims.insert("email".to_owned(), Value::String(ACCESS_EMAIL.to_owned()));
    claims.insert("type".to_owned(), Value::String("app".to_owned()));
    claims.insert("exp".to_owned(), json!(now + 300));
    claims.insert("nbf".to_owned(), json!(now - 60));
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(ACCESS_KID.to_owned());
    Ok(encode(
        &header,
        &Value::Object(claims),
        &EncodingKey::from_rsa_pem(ACCESS_PRIVATE_KEY.as_bytes())?,
    )?)
}

fn management_request(
    edge: &AccessEdge,
    method: &str,
    path: &str,
    accept: &str,
    assertion: Option<&str>,
    body: &[u8],
) -> TestResult<HttpResponse> {
    origin_request(
        &edge.management_url(),
        method,
        path,
        MANAGEMENT_HOST,
        accept,
        assertion,
        body,
    )
}

#[derive(Clone, Copy)]
struct HttpRequestSpec<'a> {
    method: &'a str,
    path: &'a str,
    host: &'a str,
    accept: &'a str,
    assertion: Option<&'a str>,
    extra_headers: &'a [(&'a str, &'a str)],
    body: &'a [u8],
}

fn management_request_with_first_post_bootstrap_recording(
    edge: &AccessEdge,
    jwks: &JwksFixture,
    request: HttpRequestSpec<'_>,
    recorder: &mut FirstPostBootstrapRecorder,
) -> TestResult<HttpResponse> {
    let raw = raw_request_with_headers(&edge.management_url(), request)?;
    recorder.record(&raw, jwks)?;
    parse_http_response(&raw.response)
}

fn callback_request(
    edge: &AccessEdge,
    method: &str,
    path: &str,
    accept: &str,
    body: &[u8],
) -> TestResult<HttpResponse> {
    origin_request(
        &edge.callback_url(),
        method,
        path,
        CALLBACK_HOST,
        accept,
        None,
        body,
    )
}

fn origin_request(
    base_url: &str,
    method: &str,
    path: &str,
    host: &str,
    accept: &str,
    assertion: Option<&str>,
    body: &[u8],
) -> TestResult<HttpResponse> {
    origin_request_with_headers(
        base_url,
        HttpRequestSpec {
            method,
            path,
            host,
            accept,
            assertion,
            extra_headers: &[],
            body,
        },
    )
}

fn origin_request_with_headers(
    base_url: &str,
    request: HttpRequestSpec<'_>,
) -> TestResult<HttpResponse> {
    let raw = raw_request_with_headers(base_url, request)?;
    record_active_callback_http("management-or-callback-http", &raw)?;
    parse_http_response(&raw.response)
}

fn raw_request(
    base_url: &str,
    method: &str,
    path: &str,
    host: &str,
    accept: &str,
    assertion: Option<&str>,
    body: &[u8],
) -> TestResult<RawHttpExchange> {
    raw_request_with_headers(
        base_url,
        HttpRequestSpec {
            method,
            path,
            host,
            accept,
            assertion,
            extra_headers: &[],
            body,
        },
    )
}

fn raw_request_with_headers(
    base_url: &str,
    request_spec: HttpRequestSpec<'_>,
) -> TestResult<RawHttpExchange> {
    let HttpRequestSpec {
        method,
        path,
        host,
        accept,
        assertion,
        extra_headers,
        body,
    } = request_spec;
    let exchange_started = Instant::now();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nAccept: {accept}\r\nConnection: close\r\n"
    );
    if let Some(assertion) = assertion {
        request.push_str("Cf-Access-Jwt-Assertion: ");
        request.push_str(assertion);
        request.push_str("\r\n");
    }
    for (name, value) in extra_headers {
        if name.bytes().any(|byte| byte == b'\r' || byte == b'\n')
            || value.bytes().any(|byte| byte == b'\r' || byte == b'\n')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "test header contained a line break",
            )
            .into());
        }
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    if !body.is_empty() {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    let mut request_bytes = request.into_bytes();
    request_bytes.extend_from_slice(body);
    let mut response = Vec::new();
    let mut response_chunks = Vec::new();

    let url = match Url::parse(base_url) {
        Ok(url) => url,
        Err(_) => {
            return Ok(terminal_raw_exchange(
                &request_bytes,
                &response,
                &response_chunks,
                exchange_started,
                0,
                None,
                TransportTermination::SafeError,
            ));
        }
    };
    let Some(host_name) = url.host_str() else {
        return Ok(terminal_raw_exchange(
            &request_bytes,
            &response,
            &response_chunks,
            exchange_started,
            0,
            None,
            TransportTermination::SafeError,
        ));
    };
    let Some(port) = url.port_or_known_default() else {
        return Ok(terminal_raw_exchange(
            &request_bytes,
            &response,
            &response_chunks,
            exchange_started,
            0,
            None,
            TransportTermination::SafeError,
        ));
    };
    let mut stream = match TcpStream::connect((host_name, port)) {
        Ok(stream) => stream,
        Err(_) => {
            return Ok(terminal_raw_exchange(
                &request_bytes,
                &response,
                &response_chunks,
                exchange_started,
                0,
                None,
                TransportTermination::SafeError,
            ));
        }
    };
    if stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .is_err()
        || stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .is_err()
    {
        return Ok(terminal_raw_exchange(
            &request_bytes,
            &response,
            &response_chunks,
            exchange_started,
            0,
            None,
            TransportTermination::SafeError,
        ));
    }
    if stream.write_all(&request_bytes).is_err() {
        let write_error_elapsed_us = exchange_started.elapsed().as_micros();
        return Ok(terminal_raw_exchange(
            &request_bytes,
            &response,
            &response_chunks,
            exchange_started,
            write_error_elapsed_us,
            Some(write_error_elapsed_us),
            TransportTermination::SafeError,
        ));
    }
    let request_write_finished_at = Instant::now();
    let request_write_elapsed_us = request_write_finished_at
        .duration_since(exchange_started)
        .as_micros();
    let response_timing_origin = Instant::now();
    let mut buffer = [0_u8; 8192];
    let termination = loop {
        match stream.read(&mut buffer) {
            Ok(0) => {
                break TransportTermination::Complete;
            }
            Ok(read) => {
                response_chunks.push(RawResponseChunk {
                    offset_us: response_timing_origin.elapsed().as_micros(),
                    bytes: buffer[..read].to_vec(),
                });
                response.extend_from_slice(&buffer[..read]);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                break TransportTermination::Timeout;
            }
            Err(_) => {
                break TransportTermination::SafeError;
            }
        }
    };
    Ok(RawHttpExchange {
        request: request_bytes,
        response,
        response_chunks,
        request_write_elapsed_us,
        write_error_elapsed_us: None,
        total_elapsed_us: exchange_started.elapsed().as_micros(),
        termination,
    })
}

struct SseConnection {
    stream: TcpStream,
    buffered: Vec<u8>,
    request: Vec<u8>,
}

fn open_sse_connection(
    base_url: &str,
    path: &str,
    host: &str,
    assertion: &str,
) -> TestResult<SseConnection> {
    let url = Url::parse(base_url)?;
    let host_name = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "SSE origin URL has no host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "SSE origin URL has no port"))?;
    let mut stream = TcpStream::connect((host_name, port))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: text/event-stream\r\nCf-Access-Jwt-Assertion: {assertion}\r\nConnection: keep-alive\r\n\r\n"
    );
    let request = request.into_bytes();
    stream.write_all(&request)?;
    let mut buffered = Vec::new();
    let header_end = loop {
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "SSE connection ended before headers",
            )
            .into());
        }
        buffered.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffered.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        if buffered.len() > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SSE response headers were too large",
            )
            .into());
        }
    };
    let status = std::str::from_utf8(&buffered[..header_end])?
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "SSE status malformed"))?
        .parse::<u16>()?;
    if status != 200 {
        return Err(io::Error::other(format!(
            "management SSE route returned HTTP {status}, expected 200"
        ))
        .into());
    }
    Ok(SseConnection {
        stream,
        buffered: buffered[header_end..].to_vec(),
        request,
    })
}

impl SseConnection {
    fn read_until_terminal(mut self) -> TestResult<Vec<u8>> {
        let mut bytes = std::mem::take(&mut self.buffered);
        let deadline = SystemTime::now() + Duration::from_secs(20);
        loop {
            if bytes
                .windows(b"completed".len())
                .any(|window| window == b"completed")
            {
                let response_chunks = if bytes.is_empty() {
                    Vec::new()
                } else {
                    vec![RawResponseChunk {
                        offset_us: 0,
                        bytes: bytes.clone(),
                    }]
                };
                let exchange = terminal_raw_exchange(
                    &self.request,
                    &bytes,
                    &response_chunks,
                    Instant::now(),
                    0,
                    None,
                    TransportTermination::Complete,
                );
                record_active_callback_http("management-sse", &exchange)?;
                return Ok(bytes);
            }
            if SystemTime::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "management SSE did not reach terminal callback state",
                )
                .into());
            }
            let mut chunk = [0_u8; 4096];
            match self.stream.read(&mut chunk) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "management SSE ended before terminal callback state",
                    )
                    .into());
                }
                Ok(read) => bytes.extend_from_slice(&chunk[..read]),
                Err(error) if error.kind() == io::ErrorKind::TimedOut => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }
}

const LOCAL_ZODE_LOGIN_MARKERS: &[&str] = &[
    "<input type=\"password\"",
    "name=\"token\"",
    "/v1/login",
    "/v1/logout",
    "href=\"/login\"",
    "href=\"/logout\"",
    "type=\"password\"",
    "cf_authorization",
    "create account",
];

fn check_html_response(label: &str, response: &HttpResponse, failures: &mut Vec<String>) {
    if response.status != 200 {
        failures.push(format!(
            "{label} returned HTTP {}, expected 200",
            response.status
        ));
    }
    if !has_html_content_type(response) {
        failures.push(format!("{label} did not declare text/html content type"));
    }
    let body = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
    if !body.contains("<!doctype html") && !body.contains("<html") {
        failures.push(format!("{label} did not return an application HTML shell"));
    }
    for marker in LOCAL_ZODE_LOGIN_MARKERS {
        if body.contains(marker) {
            failures.push(format!(
                "{label} rendered a local Zode login marker {marker}"
            ));
        }
    }
    check_safe_html_cache(label, response, failures);
}

fn check_asset_response(label: &str, response: &HttpResponse, failures: &mut Vec<String>) {
    if response.status != 200 {
        failures.push(format!(
            "{label} returned HTTP {}, expected 200",
            response.status
        ));
    }
    let content_type = header(response, "content-type").unwrap_or_default();
    if !content_type.to_ascii_lowercase().contains("javascript")
        && !content_type.to_ascii_lowercase().contains("ecmascript")
        && !content_type.to_ascii_lowercase().contains("text/css")
    {
        failures.push(format!("{label} did not declare a JavaScript content type"));
    }
    if response.body.is_empty()
        || response
            .body
            .windows(b"<html".len())
            .any(|window| window == b"<html")
    {
        failures.push(format!("{label} was empty or returned the HTML shell"));
    }
    let cache = header(response, "cache-control")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !cache.contains("immutable") {
        failures.push(format!(
            "{label} did not use an immutable versioned cache policy"
        ));
    }
    if !parse_positive_max_age(&cache) {
        failures.push(format!(
            "{label} did not use a positive integer Cache-Control max-age"
        ));
    }
}

fn assert_response_unchanged(
    label: &str,
    expected: &HttpResponse,
    actual: &HttpResponse,
    failures: &mut Vec<String>,
) {
    if expected.status != actual.status || expected.body != actual.body {
        failures.push(format!(
            "{label} changed after the test-owned tree was deleted/modified"
        ));
        return;
    }
    for header_name in ["content-type", "cache-control"] {
        if header(expected, header_name) != header(actual, header_name) {
            failures.push(format!(
                "{label} changed its {header_name} metadata after the test-owned tree was deleted/modified"
            ));
        }
    }
}

fn check_json_response(label: &str, response: &HttpResponse, failures: &mut Vec<String>) {
    if response.status != 200 {
        failures.push(format!(
            "{label} returned HTTP {}, expected 200",
            response.status
        ));
    }
    let content_type = header(response, "content-type").unwrap_or_default();
    if !content_type
        .to_ascii_lowercase()
        .contains("application/json")
    {
        failures.push(format!(
            "{label} did not declare application/json content type"
        ));
    }
    match serde_json::from_slice::<Value>(&response.body) {
        Ok(value) if value["schema"] == "zode.system.v1" => {}
        Ok(_) => failures.push(format!(
            "{label} did not return the versioned system schema"
        )),
        Err(error) => failures.push(format!("{label} returned invalid JSON: {error}")),
    }
}

fn check_system_response(label: &str, response: &HttpResponse, failures: &mut Vec<String>) {
    check_json_response(label, response, failures);
    let expected = json!({
        "schema": "zode.system.v1",
        "deployment": "server_only",
        "local_endpoint_id": null,
        "ingress": {
            "management_auth": "cloudflare_access",
            "callback_origin": "separate"
        },
        "features": {
            "remote_endpoints": true,
            "provider_auth": true
        }
    });
    match serde_json::from_slice::<Value>(&response.body) {
        Ok(actual) if actual == expected => {}
        Ok(_) => failures.push(format!(
            "{label} did not exactly match the server_only system contract"
        )),
        Err(_) => {}
    }
}

fn extract_versioned_asset_hrefs(body: &[u8]) -> Vec<String> {
    let Ok(html) = std::str::from_utf8(body) else {
        return Vec::new();
    };
    let mut assets = Vec::new();
    for attribute in ["src", "href"] {
        let mut remaining = html;
        while let Some(index) = remaining.find(attribute) {
            let after_attribute = &remaining[index + attribute.len()..];
            let after = after_attribute.trim_start();
            let Some(after) = after.strip_prefix('=') else {
                remaining = after_attribute;
                continue;
            };
            let after = after.trim_start();
            let Some(quote) = after.as_bytes().first().copied() else {
                break;
            };
            if quote != b'"' && quote != b'\'' {
                remaining = after_attribute;
                continue;
            }
            let value = &after[1..];
            let Some(end) = value.find(char::from(quote)) else {
                break;
            };
            let Some(candidate) = value[..end].split(['?', '#']).next() else {
                remaining = &value[end + 1..];
                continue;
            };
            if is_versioned_asset_path(candidate) && !assets.iter().any(|asset| asset == candidate)
            {
                assets.push(candidate.to_owned());
            }
            remaining = &value[end + 1..];
        }
    }
    assets
}

fn is_versioned_asset_path(path: &str) -> bool {
    let Some(file_name) = path.strip_prefix("/assets/") else {
        return false;
    };
    if file_name.is_empty() || file_name.contains('/') || file_name.contains("..") {
        return false;
    }
    let Some((stem, extension)) = file_name.rsplit_once('.') else {
        return false;
    };
    if !matches!(extension, "js" | "mjs" | "css") {
        return false;
    }
    let Some((_, hash)) = stem.rsplit_once('-') else {
        return false;
    };
    hash.len() >= 8
        && hash
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
}

fn parse_positive_max_age(cache_control: &str) -> bool {
    cache_control.split(',').any(|directive| {
        let Some(value) = directive.trim().strip_prefix("max-age=") else {
            return false;
        };
        !value.is_empty()
            && value.chars().all(|character| character.is_ascii_digit())
            && value.parse::<u64>().is_ok_and(|seconds| seconds > 0)
    })
}

fn check_safe_callback_404_surface(
    label: &str,
    response: &HttpResponse,
    baseline: &HttpResponse,
    failures: &mut Vec<String>,
) {
    if baseline.status != 404 {
        failures.push(format!(
            "{label} baseline returned HTTP {}, expected the callback safe 404 surface",
            baseline.status
        ));
    }
    if response.status != 404 {
        failures.push(format!(
            "{label} returned HTTP {}, expected the callback safe 404 surface",
            response.status
        ));
    }
    if response.status != baseline.status || response.body != baseline.body {
        failures.push(format!(
            "{label} did not match the callback safe 404 status/body surface"
        ));
    }
    for header_name in ["content-type", "cache-control"] {
        if header(response, header_name) != header(baseline, header_name) {
            failures.push(format!(
                "{label} did not match the callback safe 404 {header_name} surface"
            ));
        }
    }
    check_not_html(label, response, failures);
    check_no_store(label, response, failures);
    check_no_cookie(label, response, failures);
}

fn check_not_html(label: &str, response: &HttpResponse, failures: &mut Vec<String>) {
    let content_type = header(response, "content-type").unwrap_or_default();
    if content_type.to_ascii_lowercase().contains("text/html") {
        failures.push(format!("{label} was swallowed by the SPA HTML fallback"));
    }
    let body = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
    if body.contains("<!doctype html") || body.contains("<html") {
        failures.push(format!("{label} returned the SPA HTML shell"));
    }
}

fn check_no_store(label: &str, response: &HttpResponse, failures: &mut Vec<String>) {
    let cache = header(response, "cache-control")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !cache.contains("no-store") {
        failures.push(format!("{label} did not use Cache-Control: no-store"));
    }
}

fn check_safe_html_cache(label: &str, response: &HttpResponse, failures: &mut Vec<String>) {
    if !has_safe_html_cache(response) {
        failures.push(format!("{label} used a cacheable HTML policy"));
    }
}

fn has_safe_html_cache(response: &HttpResponse) -> bool {
    let cache = header(response, "cache-control")
        .unwrap_or_default()
        .to_ascii_lowercase();
    cache.contains("no-cache") || cache.contains("no-store")
}

fn has_html_content_type(response: &HttpResponse) -> bool {
    header(response, "content-type")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .contains("text/html")
}

fn has_application_html_shell(response: &HttpResponse) -> bool {
    let body = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
    body.contains("<!doctype html") || body.contains("<html")
}

fn has_no_local_login_markers(response: &HttpResponse) -> bool {
    let body = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
    !LOCAL_ZODE_LOGIN_MARKERS
        .iter()
        .any(|marker| body.contains(*marker))
}

fn response_contains_markers(response: &HttpResponse, markers: &[String]) -> bool {
    response
        .headers
        .iter()
        .any(|(_, value)| markers.iter().any(|marker| value.contains(marker)))
        || markers.iter().any(|marker| {
            response
                .body
                .windows(marker.len())
                .any(|window| window == marker.as_bytes())
        })
}

fn has_no_cookie(response: &HttpResponse) -> bool {
    header(response, "set-cookie").is_none()
}

fn scan_response(
    label: &str,
    response: &HttpResponse,
    markers: &[String],
    failures: &mut Vec<String>,
) {
    if response_contains_markers(response, markers) {
        failures.push(format!(
            "{label} response header disclosed a captured marker"
        ));
    }
}

fn check_no_cookie(label: &str, response: &HttpResponse, failures: &mut Vec<String>) {
    if !has_no_cookie(response) {
        failures.push(format!("{label} set a local application cookie"));
    }
}

fn header<'a>(response: &'a HttpResponse, name: &str) -> Option<&'a str> {
    response
        .headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn scan_server_artifacts(
    capture: &ServerCapture,
    root: &Path,
    failures: &mut Vec<String>,
    markers: &[String],
) -> TestResult {
    let mut forbidden = vec![ACCESS_SUBJECT.to_owned(), ACCESS_EMAIL.to_owned()];
    forbidden.extend_from_slice(markers);
    scan_bytes("Server stdout", &capture.stdout, &forbidden, failures);
    scan_bytes("Server stderr", &capture.stderr, &forbidden, failures);
    scan_tree(root, &forbidden, failures)?;
    Ok(())
}

fn scan_bytes(label: &str, bytes: &[u8], markers: &[String], failures: &mut Vec<String>) {
    if markers.iter().any(|marker| {
        bytes
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
    }) {
        failures.push(format!(
            "{label} disclosed an Access identity/assertion marker"
        ));
    }
}

fn scan_tree(root: &Path, markers: &[String], failures: &mut Vec<String>) -> io::Result<()> {
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            scan_tree(&path, markers, failures)?;
        } else if path.is_file() {
            let bytes = fs::read(&path)?;
            scan_bytes("Server temporary store", &bytes, markers, failures);
        }
    }
    Ok(())
}

fn scan_secret_free(bytes: &[u8], markers: &[&str]) -> TestResult {
    let static_markers = ["-----BEGIN", "eyJ", ACCESS_SUBJECT, ACCESS_EMAIL];
    if static_markers.iter().chain(markers.iter()).any(|marker| {
        bytes
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
    }) {
        return Err(
            io::Error::other("UI delivery recording retained secret or identity material").into(),
        );
    }
    Ok(())
}

fn write_new_json(path: &Path, value: &Value, mode: u32) -> TestResult {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    set_permissions(path, mode)?;
    Ok(())
}

fn promote_immutable_cassette(source: &Path, destination: &Path) -> TestResult {
    if destination.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "UI delivery cassette promotion refuses to overwrite an existing artifact",
        )
        .into());
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = fs::read(source)?;
    scan_secret_free(&bytes, &[])?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    set_permissions(destination, 0o444)?;
    Ok(())
}

fn set_permissions(path: &Path, mode: u32) -> TestResult {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(mode);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> TestResult<String> {
    let mut command = Command::new("shasum");
    command
        .arg("-a")
        .arg("256")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("shasum stdin unavailable"))?
        .write_all(bytes)?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(io::Error::other("shasum failed while recording UI delivery cassette").into());
    }
    let digest = String::from_utf8(output.stdout)?
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();
    if digest.len() != 64 {
        return Err(io::Error::other("shasum returned an invalid digest").into());
    }
    Ok(digest)
}

fn trim_ascii_space(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t'))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !matches!(byte, b' ' | b'\t'))
        .map(|index| index + 1)
        .unwrap_or(start);
    &bytes[start..end]
}

fn parse_hex_hint(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() {
        return None;
    }
    bytes.iter().try_fold(0_usize, |value, byte| {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        value.checked_mul(16)?.checked_add(digit as usize)
    })
}

fn parse_http_response(bytes: &[u8]) -> TestResult<HttpResponse> {
    let header_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP headers incomplete"))?;
    let header_text = std::str::from_utf8(&bytes[..header_end]).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("HTTP request headers were not UTF-8: {error}"),
        )
    })?;
    let mut lines = header_text.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP status malformed"))?
        .parse::<u16>()?;
    let mut headers = Vec::new();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP header malformed"))?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    let raw_body = &bytes[header_end + 4..];
    let transfer_encoding = headers
        .iter()
        .find(|(name, _)| name == "transfer-encoding")
        .map(|(_, value)| value.to_ascii_lowercase());
    let content_lengths = headers
        .iter()
        .filter(|(name, _)| name == "content-length")
        .map(|(_, value)| value.parse::<usize>())
        .collect::<Result<Vec<_>, _>>()?;
    if content_lengths
        .windows(2)
        .any(|lengths| lengths[0] != lengths[1])
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "conflicting HTTP Content-Length headers",
        )
        .into());
    }
    let is_chunked = transfer_encoding
        .as_deref()
        .is_some_and(|value| value.split(',').any(|token| token.trim() == "chunked"));
    if is_chunked && !content_lengths.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP response had both chunked transfer encoding and Content-Length",
        )
        .into());
    }
    let body = if is_chunked {
        decode_chunked(raw_body)?
    } else if let Some(&length) = content_lengths.first() {
        if raw_body.len() != length {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTP Content-Length did not exactly consume the response body",
            )
            .into());
        }
        raw_body.to_vec()
    } else {
        raw_body.to_vec()
    };
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

fn decode_chunked(mut bytes: &[u8]) -> TestResult<Vec<u8>> {
    let mut decoded = Vec::new();
    loop {
        let line_end = bytes
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunk size missing"))?;
        let size_line = &bytes[..line_end];
        let size_token = size_line
            .split(|byte| *byte == b';')
            .next()
            .map(trim_ascii_space)
            .unwrap_or_default();
        let size = parse_hex_hint(size_token)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunk size malformed"))?;
        bytes = &bytes[line_end + 2..];
        if size == 0 {
            loop {
                let trailer_end = bytes
                    .windows(2)
                    .position(|window| window == b"\r\n")
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "chunk trailers incomplete")
                    })?;
                let trailer = &bytes[..trailer_end];
                bytes = &bytes[trailer_end + 2..];
                if trailer.is_empty() {
                    if !bytes.is_empty() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "bytes followed the complete chunked response",
                        )
                        .into());
                    }
                    return Ok(decoded);
                }
                if !trailer.contains(&b':') {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "chunk trailer malformed",
                    )
                    .into());
                }
            }
        }
        let required = size
            .checked_add(2)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunk size overflow"))?;
        if bytes.len() < required || &bytes[size..size + 2] != b"\r\n" {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "chunk truncated").into());
        }
        decoded.extend_from_slice(&bytes[..size]);
        bytes = &bytes[size + 2..];
    }
}

fn read_request(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP request too large",
            ));
        }
    }
    let header_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP request headers incomplete",
            )
        })?;
    let header_text = std::str::from_utf8(&bytes[..header_end]).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("HTTP request headers were not UTF-8: {error}"),
        )
    })?;
    let content_length = header_text
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            (name.eq_ignore_ascii_case("content-length")).then(|| value.trim().parse::<usize>())
        })
        .transpose()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "content length malformed"))?
        .unwrap_or(0);
    while bytes.len() < header_end + content_length {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    if bytes.len() < header_end + content_length {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "HTTP request body incomplete",
        ));
    }
    Ok(bytes)
}

fn has_header(request: &[u8], name: &str) -> bool {
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or(request.len());
    String::from_utf8_lossy(&request[..header_end])
        .lines()
        .any(|line| {
            line.split_once(':')
                .is_some_and(|(key, _)| key.eq_ignore_ascii_case(name))
        })
}

fn edge_reject(mut stream: TcpStream) -> io::Result<()> {
    let body = b"{\"error\":{\"code\":\"access_required\",\"retryable\":false}}";
    let response = format!(
        "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.write_all(body)
}

fn proxy_connection(
    mut client: TcpStream,
    target: SocketAddr,
    require_access: bool,
) -> io::Result<()> {
    let request = read_request(&mut client)?;
    if require_access && !has_header(&request, "Cf-Access-Jwt-Assertion") {
        return edge_reject(client);
    }
    let mut upstream = TcpStream::connect(target)?;
    // The listener is a nonblocking fixture, but every accepted stream is
    // restored to blocking mode before this function. Keep that barrier
    // explicit for the upstream side as well: otherwise a platform may
    // surface EAGAIN (os error 35) while the Server is still writing SSE
    // headers, which is exactly the historical callback gap.
    upstream.set_nonblocking(false)?;
    upstream.set_read_timeout(Some(Duration::from_millis(250)))?;
    upstream.set_write_timeout(Some(Duration::from_secs(5)))?;
    upstream.write_all(&request)?;
    let mut response = Vec::new();
    let mut response_started = false;
    let mut buffer = [0_u8; 8192];
    loop {
        match upstream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                response_started = true;
                response.extend_from_slice(&buffer[..read]);
                client.write_all(&buffer[..read])?;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset && response_started => {
                break;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

struct AccessEdge {
    management_address: SocketAddr,
    callback_address: SocketAddr,
    stop: Arc<AtomicBool>,
    joins: Vec<JoinHandle<()>>,
    connections: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl AccessEdge {
    fn start(server_url: &str) -> TestResult<Self> {
        let target = parse_socket_addr(server_url)?;
        let management_listener = TcpListener::bind("127.0.0.1:0")?;
        let callback_listener = TcpListener::bind("127.0.0.1:0")?;
        management_listener.set_nonblocking(true)?;
        callback_listener.set_nonblocking(true)?;
        let management_address = management_listener.local_addr()?;
        let callback_address = callback_listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(Mutex::new(Vec::new()));
        let joins = vec![
            spawn_edge_listener(
                management_listener,
                target,
                true,
                Arc::clone(&stop),
                Arc::clone(&connections),
            ),
            spawn_edge_listener(
                callback_listener,
                target,
                false,
                Arc::clone(&stop),
                Arc::clone(&connections),
            ),
        ];
        Ok(Self {
            management_address,
            callback_address,
            stop,
            joins,
            connections,
        })
    }

    fn management_url(&self) -> String {
        format!("http://{}", self.management_address)
    }

    fn callback_url(&self) -> String {
        format!("http://{}", self.callback_address)
    }
}

impl Drop for AccessEdge {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.management_address);
        let _ = TcpStream::connect(self.callback_address);
        for join in self.joins.drain(..) {
            let _ = join.join();
        }
        if let Ok(mut connections) = self.connections.lock() {
            for join in connections.drain(..) {
                let _ = join.join();
            }
        }
    }
}

fn spawn_edge_listener(
    listener: TcpListener,
    target: SocketAddr,
    require_access: bool,
    stop: Arc<AtomicBool>,
    connections: Arc<Mutex<Vec<JoinHandle<()>>>>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        while !stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _)) => {
                    // Keep the accepted listener responsive while an SSE
                    // connection remains open. A single inline proxy would
                    // starve the following message/callback request and
                    // report a misleading timeout instead of exercising the
                    // product path.
                    let connection = thread::spawn(move || {
                        let _ = (|| -> io::Result<()> {
                            // TcpStream inherits the listener's nonblocking
                            // mode on this platform; restore blocking before
                            // the first request read so the fixture has an
                            // explicit barrier.
                            stream.set_nonblocking(false)?;
                            proxy_connection(stream, target, require_access)
                        })();
                    });
                    if let Ok(mut active) = connections.lock() {
                        active.push(connection);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    })
}

#[derive(Clone, Debug)]
struct CapturedToolInvocation {
    body: Value,
    authorization: Option<String>,
}

struct BoundaryFixtureState {
    invocation: Option<CapturedToolInvocation>,
    released: bool,
}

struct CallbackBoundaryFixture {
    address: SocketAddr,
    state: Arc<(Mutex<BoundaryFixtureState>, Condvar)>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl CallbackBoundaryFixture {
    fn start() -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let state = Arc::new((
            Mutex::new(BoundaryFixtureState {
                invocation: None,
                released: false,
            }),
            Condvar::new(),
        ));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_state = Arc::clone(&state);
        let thread_stop = Arc::clone(&stop);
        let join = thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = (|| -> io::Result<()> {
                            stream.set_nonblocking(false)?;
                            serve_callback_boundary(stream, &thread_state)
                        })();
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            address,
            state,
            stop,
            join: Some(join),
        })
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.address)
    }

    fn tool_url(&self) -> String {
        format!("{}/invoke", self.base_url())
    }

    fn provider_base_url(&self) -> String {
        format!("{}/v1", self.base_url())
    }

    fn wait_for_invocation(&self) -> TestResult<CapturedToolInvocation> {
        let (lock, wake) = &*self.state;
        let mut state = lock.lock().map_err(|_| "callback fixture mutex poisoned")?;
        let deadline = SystemTime::now() + Duration::from_secs(10);
        loop {
            if let Some(invocation) = state.invocation.clone() {
                return Ok(invocation);
            }
            let remaining = deadline
                .duration_since(SystemTime::now())
                .unwrap_or_default();
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "callback tool fixture invocation barrier timed out",
                )
                .into());
            }
            let (next, result) = wake
                .wait_timeout(state, remaining)
                .map_err(|_| "callback fixture condvar wait failed")?;
            state = next;
            if result.timed_out() && state.invocation.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "callback tool fixture invocation barrier timed out",
                )
                .into());
            }
        }
    }

    fn release(&self) -> TestResult {
        let (lock, wake) = &*self.state;
        let mut state = lock.lock().map_err(|_| "callback fixture mutex poisoned")?;
        state.released = true;
        wake.notify_all();
        Ok(())
    }
}

impl Drop for CallbackBoundaryFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = self.release();
        let _ = TcpStream::connect(self.address);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn serve_callback_boundary(
    mut stream: TcpStream,
    state: &Arc<(Mutex<BoundaryFixtureState>, Condvar)>,
) -> io::Result<()> {
    let request = read_request(&mut stream)?;
    let path = request
        .split(|byte| *byte == b' ')
        .nth(1)
        .and_then(|path| std::str::from_utf8(path).ok())
        .unwrap_or_default();
    if path.starts_with("/v1/chat/completions") {
        let body = concat!(
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"callback-call\",\"type\":\"function\",\"function\":{\"name\":\"callback_tool\",\"arguments\":\"{\\\"value\\\":\\\"fixture\\\"}\"}}]},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
            "data: [DONE]\n\n"
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        return stream.write_all(response.as_bytes());
    }
    if path.starts_with("/invoke") {
        let body = request_body(&request).unwrap_or_default();
        let invocation = CapturedToolInvocation {
            body: serde_json::from_slice(&body).unwrap_or(Value::Null),
            authorization: request_header(&request, "authorization"),
        };
        let (lock, wake) = &**state;
        let mut fixture = lock
            .lock()
            .map_err(|_| io::Error::other("callback fixture mutex poisoned"))?;
        fixture.invocation = Some(invocation);
        wake.notify_all();
        while !fixture.released {
            fixture = wake
                .wait(fixture)
                .map_err(|_| io::Error::other("callback fixture condvar wait failed"))?;
        }
        let response_body =
            br#"{"status":"accepted","result":{"content":"fixture callback accepted"}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response_body.len()
        );
        stream.write_all(response.as_bytes())?;
        return stream.write_all(response_body);
    }
    let response_body = b"{}";
    let response = format!(
        "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response_body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.write_all(response_body)
}

fn request_header(request: &[u8], name: &str) -> Option<String> {
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?;
    String::from_utf8_lossy(&request[..header_end])
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
}

fn request_body(request: &[u8]) -> Option<Vec<u8>> {
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?;
    let length = request_header(request, "content-length")?
        .parse::<usize>()
        .ok()?;
    request
        .get(header_end + 4..header_end + 4 + length)
        .map(ToOwned::to_owned)
}

#[derive(Clone)]
struct JwksExchange {
    sequence: usize,
    request: Vec<u8>,
    response_wire: Option<Vec<u8>>,
    terminal: &'static str,
    completion: &'static str,
    response_write_succeeded: bool,
}

struct JwksFixture {
    address: SocketAddr,
    exchanges: Arc<Mutex<Vec<JwksExchange>>>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl JwksFixture {
    fn start() -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let exchanges = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_exchanges = Arc::clone(&exchanges);
        let thread_stop = Arc::clone(&stop);
        let join = thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = (|| -> io::Result<()> {
                            stream.set_nonblocking(false)?;
                            serve_jwks(stream, &thread_exchanges)
                        })();
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            address,
            exchanges,
            stop,
            join: Some(join),
        })
    }

    fn issuer(&self) -> String {
        format!("http://{}/", self.address)
    }

    fn jwks_url(&self) -> String {
        format!("http://{}/jwks", self.address)
    }

    fn exchange_snapshot(&self) -> TestResult<Vec<JwksExchange>> {
        self.exchanges
            .lock()
            .map(|exchanges| exchanges.clone())
            .map_err(|_| io::Error::other("JWKS exchange ledger lock poisoned").into())
    }
}

impl Drop for JwksFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        if let Ok(exchanges) = self.exchanges.lock() {
            let _ = record_active_callback_jwks(&exchanges);
        }
    }
}

fn serve_jwks(mut stream: TcpStream, exchanges: &Mutex<Vec<JwksExchange>>) -> io::Result<()> {
    let request = read_request(&mut stream)?;
    let body = json!({
        "keys": [{
            "kty": "RSA",
            "kid": ACCESS_KID,
            "use": "sig",
            "alg": "RS256",
            "n": ACCESS_MODULUS,
            "e": "AQAB"
        }]
    })
    .to_string();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(), body
    );
    let response = response.into_bytes();
    let write_result = stream.write_all(&response);
    let (response_wire, terminal, completion, response_write_succeeded) = match &write_result {
        Ok(()) => (
            Some(response),
            "complete",
            "response_write_all_succeeded",
            true,
        ),
        Err(error) => (
            None,
            jwks_write_terminal(error),
            "response_write_failed",
            false,
        ),
    };
    let mut exchanges = exchanges
        .lock()
        .map_err(|_| io::Error::other("JWKS exchange ledger lock poisoned"))?;
    let sequence = exchanges.len();
    exchanges.push(JwksExchange {
        sequence,
        request,
        response_wire,
        terminal,
        completion,
        response_write_succeeded,
    });
    drop(exchanges);
    write_result
}

fn jwks_write_terminal(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => "timeout",
        io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::NotConnected
        | io::ErrorKind::UnexpectedEof => "disconnect",
        _ => "safe_error",
    }
}

fn parse_socket_addr(base_url: &str) -> TestResult<SocketAddr> {
    let url = Url::parse(base_url)?;
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "server URL has no host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "server URL has no port"))?;
    let address = format!("{host}:{port}").parse::<SocketAddr>()?;
    Ok(address)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransportTermination {
    Complete,
    Disconnect,
    Timeout,
    SafeError,
}

impl TransportTermination {
    fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Disconnect => "disconnect",
            Self::Timeout => "timeout",
            Self::SafeError => "safe_error",
        }
    }
}

struct RawHttpExchange {
    request: Vec<u8>,
    response: Vec<u8>,
    response_chunks: Vec<RawResponseChunk>,
    request_write_elapsed_us: u128,
    write_error_elapsed_us: Option<u128>,
    total_elapsed_us: u128,
    termination: TransportTermination,
}

#[derive(Clone)]
struct RawResponseChunk {
    offset_us: u128,
    bytes: Vec<u8>,
}

fn terminal_raw_exchange(
    request: &[u8],
    response: &[u8],
    response_chunks: &[RawResponseChunk],
    exchange_started: Instant,
    request_write_elapsed_us: u128,
    write_error_elapsed_us: Option<u128>,
    termination: TransportTermination,
) -> RawHttpExchange {
    RawHttpExchange {
        request: request.to_vec(),
        response: response.to_vec(),
        response_chunks: response_chunks.to_vec(),
        request_write_elapsed_us,
        write_error_elapsed_us,
        total_elapsed_us: exchange_started.elapsed().as_micros(),
        termination,
    }
}

fn raw_exchange_envelope(
    recording_id: &str,
    e2e_name: &str,
    purpose: &str,
    exchange: &RawHttpExchange,
) -> Value {
    raw_exchange_envelope_with_boundary(
        recording_id,
        e2e_name,
        "management_http",
        purpose,
        exchange,
    )
}

fn raw_exchange_envelope_with_boundary(
    recording_id: &str,
    e2e_name: &str,
    boundary: &str,
    purpose: &str,
    exchange: &RawHttpExchange,
) -> Value {
    json!({
        "schema": "zode.http-incident-recording.v1",
        "version": 1,
        "recording_id": recording_id,
        "e2e_name": e2e_name,
        "capture_class": "raw_quarantine",
        "purpose": purpose,
        "boundary": boundary,
        "test_only": true,
        "bootstrap_barrier": "ZODE_SERVER_READY",
        "request_wire_hex": bytes_hex(&exchange.request),
        "response_wire_hex": bytes_hex(&exchange.response),
        "response_chunks": raw_response_chunks(&exchange.response_chunks),
        "timing": {
            "request_write_us": exchange.request_write_elapsed_us,
            "write_error_elapsed_us": exchange.write_error_elapsed_us,
            "response_total_us": exchange
                .total_elapsed_us
                .saturating_sub(exchange.request_write_elapsed_us),
            "total_us": exchange.total_elapsed_us
        },
        "termination": exchange.termination.as_str(),
        "transport_termination": exchange.termination.as_str()
    })
}

struct FirstPostBootstrapRecorder {
    root: PathBuf,
    recording_id: String,
    captured: bool,
}

impl FirstPostBootstrapRecorder {
    fn new() -> TestResult<Self> {
        let quarantine_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .ok_or_else(|| io::Error::other("server manifest has no repository parent"))?
            .join("target/test-recordings/quarantine");
        fs::create_dir_all(&quarantine_root)?;
        set_permissions(&quarantine_root, 0o700)?;
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let recording_id = format!(
            "ui-delivery-static-first-post-bootstrap-{}-{nonce}",
            std::process::id()
        );
        let root = quarantine_root.join(&recording_id);
        fs::create_dir(&root)?;
        set_permissions(&root, 0o700)?;
        Ok(Self {
            root,
            recording_id,
            captured: false,
        })
    }

    fn record(&mut self, exchange: &RawHttpExchange, jwks: &JwksFixture) -> TestResult<()> {
        if self.captured {
            return Ok(());
        }
        let raw_path = self.root.join("000001.raw.json");
        let raw_envelope = raw_exchange_envelope(
            &self.recording_id,
            INCIDENT_OWNER,
            "retain the first public management exchange before any parse or framing conversion",
            exchange,
        );
        write_restricted_new_json(&raw_path, &raw_envelope)?;
        sync_directory(&self.root)?;
        let quarantine_parent = self.root.parent().ok_or_else(|| {
            io::Error::other("first recording run directory has no quarantine parent")
        })?;
        sync_directory(quarantine_parent)?;

        let request = parse_wire_message(&exchange.request, false).ok();
        let response = parse_wire_message(&exchange.response, true).ok();
        let parsed_response = parse_http_response(&exchange.response);
        let response_status = parsed_response
            .as_ref()
            .ok()
            .map(|response| response.status)
            .or_else(|| response.as_ref().and_then(|response| response.status));
        let complete_consumption = matches!(exchange.termination, TransportTermination::Complete)
            && parsed_response.is_ok();
        let termination = if exchange.termination == TransportTermination::Complete {
            if complete_consumption {
                TransportTermination::Complete
            } else {
                TransportTermination::Disconnect
            }
        } else {
            exchange.termination
        };
        let first_safe_outcome = if complete_consumption {
            response_status
                .map(|status| format!("complete_http_{status}"))
                .unwrap_or_else(|| "safe_error".to_owned())
        } else {
            termination.as_str().to_owned()
        };
        let raw_file_digest = sha256_hex(&fs::read(&raw_path)?)?;
        let request_digest = sha256_hex(&exchange.request)?;
        let response_digest = sha256_hex(&exchange.response)?;
        let jwks_exchanges = jwks.exchange_snapshot()?;
        if jwks_exchanges.is_empty() {
            return Err(io::Error::other(
                "Access validation did not consume the test-owned JWKS fixture",
            )
            .into());
        }
        let mut jwks_exchange_records = Vec::with_capacity(jwks_exchanges.len());
        for jwks_exchange in &jwks_exchanges {
            let request_digest = sha256_hex(&jwks_exchange.request)?;
            let (response_wire_hex, response_digest, response_wire_bytes) =
                if let Some(response_wire) = &jwks_exchange.response_wire {
                    (
                        Value::String(bytes_hex(response_wire)),
                        Value::String(format!("sha256:{}", sha256_hex(response_wire)?)),
                        json!(response_wire.len()),
                    )
                } else {
                    (Value::Null, Value::Null, Value::Null)
                };
            jwks_exchange_records.push(json!({
                "sequence": jwks_exchange.sequence,
                "request_wire_hex": bytes_hex(&jwks_exchange.request),
                "request_sha256": format!("sha256:{request_digest}"),
                "response_wire_hex": response_wire_hex,
                "response_sha256": response_digest,
                "response_wire_bytes": response_wire_bytes,
                "response_write_succeeded": jwks_exchange.response_write_succeeded,
                "response_complete": jwks_exchange.response_write_succeeded
                    && jwks_exchange.response_wire.is_some(),
                "terminal": jwks_exchange.terminal,
                "completion": jwks_exchange.completion,
            }));
        }
        let captured_response_bytes = exchange
            .response_chunks
            .iter()
            .map(|chunk| chunk.bytes.len())
            .sum::<usize>();
        let chunks_cover_response = captured_response_bytes == exchange.response.len();
        let request_start_line = request.as_ref().map(|request| request.start_line.clone());
        let request_path = request.as_ref().and_then(|request| {
            request
                .start_line
                .split_whitespace()
                .nth(1)
                .map(str::to_owned)
        });
        let manifest = json!({
            "schema": "zode.http-incident-manifest.v1",
            "version": 1,
            "recording_id": self.recording_id,
            "e2e_name": INCIDENT_OWNER,
            "boundary": "management_http",
            "test_only": true,
            "committed": true,
            "bootstrap_barrier": "ZODE_SERVER_READY",
            "provenance": {
                "kind": "post_bootstrap_management_capture",
                "source_recording_id": null,
                "legacy_root_404_relation": "not_used_direct_authoritative_get"
            },
            "jwks_fixture": {
                "fixture_id": "ui-delivery-jwks-fixture",
                "issuer": jwks.issuer(),
                "jwks_url": jwks.jwks_url(),
                "access_kid": ACCESS_KID,
                "access_audience": ACCESS_AUDIENCE,
                "exchange_count": jwks_exchange_records.len(),
                "exchanges": jwks_exchange_records
            },
            "exchange": {
                "sequence": 0,
                "raw_file": "000001.raw.json",
                "request": {
                    "method": request_start_line
                        .as_deref()
                        .and_then(|line| line.split_whitespace().next()),
                    "path": request_path,
                    "authority": MANAGEMENT_AUTHORITY,
                    "access_assertion": "SLOT_ACCESS_ASSERTION",
                    "body_length": request.as_ref().map_or(0, |request| request.body_length),
                    "sha256": format!("sha256:{request_digest}")
                },
                "response": {
                    "status": response_status,
                    "termination": termination.as_str(),
                    "transport_termination": exchange.termination.as_str(),
                    "first_safe_outcome": first_safe_outcome,
                    "complete_consumption": complete_consumption,
                    "chunk_count": exchange.response_chunks.len(),
                    "body_length": exchange.response.len(),
                    "chunks_cover_response": chunks_cover_response,
                    "sha256": format!("sha256:{response_digest}")
                },
                "raw_file_sha256": format!("sha256:{raw_file_digest}"),
                "timing": {
                    "request_write_us": exchange.request_write_elapsed_us,
                    "write_error_elapsed_us": exchange.write_error_elapsed_us,
                    "response_total_us": exchange
                        .total_elapsed_us
                        .saturating_sub(exchange.request_write_elapsed_us),
                    "total_us": exchange.total_elapsed_us
                }
            }
        });
        write_restricted_new_json(&self.root.join("manifest.v1.json"), &manifest)?;
        sync_directory(&self.root)?;
        sync_directory(quarantine_parent)?;
        self.captured = true;
        Ok(())
    }

    fn record_observation(
        &self,
        root_response: &HttpResponse,
        expected_index: &[u8],
        expected_asset_hrefs: &[String],
        response_markers: &[String],
    ) -> TestResult<()> {
        if !self.captured {
            return Err(io::Error::other(
                "cannot create the root observation before raw and manifest commit",
            )
            .into());
        }
        let status_ok = root_response.status == 200;
        let body_matches_expected = root_response.body.as_slice() == expected_index;
        let content_type_ok = has_html_content_type(root_response);
        let application_shell_ok = has_application_html_shell(root_response);
        let local_login_markers_absent = has_no_local_login_markers(root_response);
        let cookie_absent = has_no_cookie(root_response);
        let secret_markers_absent = !response_contains_markers(root_response, response_markers);
        let cache_matches = has_safe_html_cache(root_response);
        let root_asset_hrefs = extract_versioned_asset_hrefs(&root_response.body);
        let asset_hrefs_parseable = !root_asset_hrefs.is_empty();
        let asset_hrefs_match_expected = root_asset_hrefs.as_slice() == expected_asset_hrefs;
        let root_contract_passed = status_ok
            && content_type_ok
            && application_shell_ok
            && local_login_markers_absent
            && cookie_absent
            && secret_markers_absent
            && body_matches_expected
            && cache_matches
            && asset_hrefs_parseable
            && asset_hrefs_match_expected;
        let body_cache_mismatch = status_ok
            && content_type_ok
            && application_shell_ok
            && local_login_markers_absent
            && cookie_absent
            && secret_markers_absent
            && body_matches_expected
            && asset_hrefs_parseable
            && asset_hrefs_match_expected
            && !cache_matches;
        let classification = if root_response.status == 404 {
            "shallow404"
        } else if root_contract_passed {
            "exact_match"
        } else if body_cache_mismatch {
            "body_cache_mismatch"
        } else {
            "other"
        };
        let raw_path = self.root.join("000001.raw.json");
        let manifest_path = self.root.join("manifest.v1.json");
        let raw_file_digest = sha256_hex(&fs::read(&raw_path)?)?;
        let manifest_digest = sha256_hex(&fs::read(&manifest_path)?)?;
        let root_body_digest = sha256_hex(&root_response.body)?;
        let expected_body_digest = sha256_hex(expected_index)?;
        let cache_control = header(root_response, "cache-control").unwrap_or_default();
        let cache_control_digest = sha256_hex(cache_control.as_bytes())?;
        let observation = json!({
            "schema": "zode.http-incident-observation.v1",
            "version": 1,
            "recording_id": self.recording_id,
            "e2e_name": INCIDENT_OWNER,
            "boundary": "management_http",
            "test_only": true,
            "safe_classification": classification,
            "safe_result": {
                "classification": classification,
                "body_cache_mismatch": body_cache_mismatch,
                "shallow404": root_response.status == 404
            },
            "root": {
                "status": root_response.status,
                "status_ok": status_ok,
                "content_type_text_html": content_type_ok,
                "application_html_shell": application_shell_ok,
                "local_login_markers_absent": local_login_markers_absent,
                "secret_markers_absent": secret_markers_absent,
                "cookie_absent": cookie_absent,
                "body_matches_expected": body_matches_expected,
                "safe_html_cache": cache_matches,
                "asset_hrefs_parseable": asset_hrefs_parseable,
                "asset_hrefs_match_expected": asset_hrefs_match_expected,
                "root_contract_passed": root_contract_passed,
                "body_sha256": format!("sha256:{root_body_digest}"),
                "expected_body_sha256": format!("sha256:{expected_body_digest}"),
                "cache_control_sha256": format!("sha256:{cache_control_digest}")
            },
            "associated_digests": {
                "raw_file": "000001.raw.json",
                "raw_file_sha256": format!("sha256:{raw_file_digest}"),
                "manifest_file": "manifest.v1.json",
                "manifest_sha256": format!("sha256:{manifest_digest}")
            }
        });
        write_restricted_new_json(
            &self.root.join("000002.root-observation.v1.json"),
            &observation,
        )?;
        let quarantine_parent = self.root.parent().ok_or_else(|| {
            io::Error::other("first recording run directory has no quarantine parent")
        })?;
        sync_directory(&self.root)?;
        sync_directory(quarantine_parent)?;
        Ok(())
    }

    fn captured(&self) -> bool {
        self.captured
    }
}

struct WireMessage {
    start_line: String,
    status: Option<u16>,
    body_length: usize,
}

fn parse_wire_message(bytes: &[u8], response: bool) -> TestResult<WireMessage> {
    let header_end = http_header_end(bytes)?;
    let header_text = std::str::from_utf8(&bytes[..header_end])?;
    let mut lines = header_text.split("\r\n");
    let start_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP start line missing"))?
        .to_owned();
    let status = if response {
        Some(
            start_line
                .split_whitespace()
                .nth(1)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP status missing"))?
                .parse::<u16>()?,
        )
    } else {
        None
    };
    for line in lines {
        let (_name, _value) = line
            .split_once(':')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP header malformed"))?;
    }
    Ok(WireMessage {
        start_line,
        status,
        body_length: bytes[header_end + 4..].len(),
    })
}

fn raw_response_chunks(chunks: &[RawResponseChunk]) -> Vec<Value> {
    let mut wire_offset = 0_usize;
    let mut raw_chunks = Vec::new();
    for chunk in chunks {
        raw_chunks.push(json!({
            "offset_us": chunk.offset_us,
            "wire_offset": wire_offset,
            "data_hex": bytes_hex(&chunk.bytes)
        }));
        wire_offset = wire_offset.saturating_add(chunk.bytes.len());
    }
    raw_chunks
}

fn http_header_end(bytes: &[u8]) -> TestResult<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP headers incomplete").into())
}

fn bytes_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn write_restricted_new_json(path: &Path, value: &Value) -> TestResult {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.write_all(b"\n")?;
    file.flush()?;
    file.sync_all()?;
    set_permissions(path, 0o600)?;
    file.sync_all()?;
    Ok(())
}

fn sync_directory(path: &Path) -> TestResult {
    let directory = OpenOptions::new().read(true).open(path)?;
    directory.sync_all()?;
    Ok(())
}

struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

struct ServerProcess {
    child: Option<Child>,
    pid: u32,
    process_name: String,
    base_url: String,
    stdout: Arc<Mutex<Vec<u8>>>,
    stderr: Arc<Mutex<Vec<u8>>>,
    readers: Vec<JoinHandle<()>>,
}

struct ServerCapture {
    pid: u32,
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl ServerProcess {
    fn start(config_path: &Path) -> TestResult<Self> {
        Self::start_in_directory(config_path, Path::new("."))
    }

    fn start_in_directory(config_path: &Path, working_directory: &Path) -> TestResult<Self> {
        let binary = env::var_os("CARGO_BIN_EXE_zode-server")
            .or_else(|| env::var_os("CARGO_BIN_EXE_zode_server"))
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "zode-server binary missing"))?;
        let mut command = Command::new(binary);
        command.current_dir(working_directory);
        command.arg("--config").arg(config_path);
        Self::start_command(command, "ZODE_SERVER_READY ", "zode-server")
    }

    fn start_endpoint(config_path: &Path) -> TestResult<Self> {
        let binary = endpoint_binary()?;
        let mut command = Command::new(binary);
        command.arg("--config").arg(config_path);
        Self::start_command(command, "ZODE_READY ", "zode Endpoint")
    }

    fn start_command(
        mut command: Command,
        ready_prefix: &'static str,
        label: &'static str,
    ) -> TestResult<Self> {
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let pid = child.id();
        let stdout = Arc::new(Mutex::new(Vec::new()));
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let (ready_tx, ready_rx) = mpsc::channel();
        let stdout_reader = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("zode-server stdout was not piped"))?;
        let stderr_reader = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("zode-server stderr was not piped"))?;
        let stdout_store = Arc::clone(&stdout);
        let stdout_thread = thread::spawn(move || {
            let mut reader = BufReader::new(stdout_reader);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        if let Ok(mut bytes) = stdout_store.lock() {
                            bytes.extend_from_slice(line.as_bytes());
                        }
                        if let Some(address) = line.strip_prefix(ready_prefix) {
                            let _ = ready_tx.send(address.trim().to_owned());
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        let stderr_store = Arc::clone(&stderr);
        let stderr_thread = thread::spawn(move || {
            let mut reader = BufReader::new(stderr_reader);
            let mut bytes = Vec::new();
            let _ = reader.read_to_end(&mut bytes);
            if let Ok(mut stored) = stderr_store.lock() {
                stored.extend_from_slice(&bytes);
            }
        });
        let base_url = match ready_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(address) => address,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{label} readiness timeout: {error}"),
                )
                .into());
            }
        };
        Ok(Self {
            child: Some(child),
            pid,
            process_name: label.to_owned(),
            base_url,
            stdout,
            stderr,
            readers: vec![stdout_thread, stderr_thread],
        })
    }

    fn stop(&mut self) -> TestResult<ServerCapture> {
        let status = if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            Some(child.wait()?)
        } else {
            None
        };
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
        let capture = ServerCapture {
            pid: self.pid,
            status: status.ok_or_else(|| io::Error::other("process was already stopped"))?,
            stdout: self
                .stdout
                .lock()
                .map_err(|_| "stdout lock poisoned")?
                .clone(),
            stderr: self
                .stderr
                .lock()
                .map_err(|_| "stderr lock poisoned")?
                .clone(),
        };
        record_active_callback_process(&self.process_name, &capture);
        Ok(capture)
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        let status = if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            child.wait().ok()
        } else {
            None
        };
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
        if let Some(status) = status {
            let capture = ServerCapture {
                pid: self.pid,
                status,
                stdout: self
                    .stdout
                    .lock()
                    .map(|bytes| bytes.clone())
                    .unwrap_or_default(),
                stderr: self
                    .stderr
                    .lock()
                    .map(|bytes| bytes.clone())
                    .unwrap_or_default(),
            };
            record_active_callback_process(&self.process_name, &capture);
        }
    }
}

fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs() as i64
}
