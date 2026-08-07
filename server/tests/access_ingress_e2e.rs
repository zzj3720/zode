use std::{
    collections::BTreeSet,
    env,
    error::Error,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc, Arc, Condvar, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use url::Url;

const ISSUER_PATH: &str = "/";
const AUDIENCE: &str = "zode-management-test";
const HUMAN_SUB: &str = "human-sub-should-not-persist";
const SERVICE_NAME: &str = "service-name-should-not-persist";
const HUMAN_EMAIL: &str = "human@example.invalid";
const JWKS_INITIAL_KID: &str = "access-initial";
const JWKS_ROTATED_KID: &str = "access-rotated";
const INCIDENT_CASSETTE_SCHEMA: &str = "zode.http-incident-recording.v1";
const INCIDENT_RECORDING_ID: &str = "access-ingress-auth-boundary-complete-20260807";
const INCIDENT_SOURCE_RECORDING_ID: &str = "access-ingress-auth-boundary-first-404-20260807";
const INCIDENT_OWNER: &str = "e2e_access_human_service_and_jwks_rotation_gate_management";
const INCIDENT_BOUNDARY: &str = "zode-server-management-http";
const INCIDENT_CASSETTE_PATH: &str =
    "tests/fixtures/incidents/access-ingress-auth-boundary-complete.v1.json";
const INCIDENT_SOURCE_CASSETTE_PATH: &str =
    "tests/fixtures/incidents/access-ingress-auth-boundary-first-404.v1.json";
const SUBJECT_KEY: &[u8; 32] = b"access-e2e-subject-key-slot-0001";
const CATALOG_CONTROLLER_AUTHORITY: &str = "access-catalog-controller";
const CATALOG_CONTROLLER_SECRET: &str = "access-catalog-controller-secret-e2e";
const CATALOG_DIRECT_SUBJECT: &str = "access-catalog-direct-probe-subject";
const CATALOG_ENDPOINT_LABEL: &str = "Access Catalog Endpoint";
const JWKS_BARRIER_TIMEOUT: Duration = Duration::from_secs(5);
const CHILD_STOP_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const IDENTITY_MARKERS: &[&str] = &[
    HUMAN_SUB,
    SERVICE_NAME,
    HUMAN_EMAIL,
    "forged-human",
    "forged@example.invalid",
    "rotated-human",
    "rotated@example.invalid",
    "expired-human",
    "expired@example.invalid",
    "future-nbf-human",
    "future-nbf@example.invalid",
    "wrong-issuer-human",
    "wrong-issuer@example.invalid",
    "wrong-audience-human",
    "wrong-audience@example.invalid",
    "unsupported-alg-human",
    "unsupported-alg@example.invalid",
    "missing-kid-human",
    "missing-kid@example.invalid",
    "missing-type-human",
    "missing-type@example.invalid",
    "missing-subject-human",
    "missing-subject@example.invalid",
    "wrong-type-human",
    "wrong-type@example.invalid",
    "ambiguous-human",
    "ambiguous-service",
    "ambiguous@example.invalid",
    "empty@example.invalid",
    "non-string@example.invalid",
    "unknown-kid-human",
    "unknown-kid@example.invalid",
    "unknown-fail-human",
    "unknown-fail@example.invalid",
];

// These are test-only fixtures. They are never written to the Server config,
// sent to the Server, or included in a failure message.
const INITIAL_PRIVATE_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
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

const ROTATED_PRIVATE_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA0j5DrRWu4jhpYjsdslMmOlJN/WMnH4tfd8DYL8XUnd0E7gvf
p9IkeUwRoErNYLIDsM5am4COpkzOTelqlrzpIpXJw6d0sn8kzS+N3/GL5rITm2yY
nY6X4nIjEgxs7fQaSabN8r8saCeHLMOipzkbsYccK1wyWAj3bHjDbIBpThHV5eVp
RHOBjf/epmVQdL6tP58Gz0iVWcbWcXdWpCIWMcOMXR6kAtNOOhBpgbHLerqosteB
ITekOpxe0Up53gREkLZz8Yb7G9BtbiYpaGRWQx+H3VdLwJhvD80RK64xV39oFpMf
8jvIzd4aNP9U6EGfuPbAZjVLOmUiNnqyLbDp0wIDAQABAoIBAACC/UgtDtVnHL6L
9UkLUcL/k0gEF0LI5I0Wj5AiM5/Eu2/W4I74gHU5Havdsr1DAaZLAkZxnCdEdZYT
9Nn0EL8wTSLoQ+zxSUYkkPxUCqqfkVOmAoMTp0P6UiKHnDZCC1RVjxfBplqEihwu
R7WPeoVGlmd2nHrBXtTJQHSBpX/2owPOoQHiSFP3Bn+XuacvxsgQT5t4yaD+LaRb
voNcKNYdoPjFMPjYy7lr8RbFjqngIxTWhojSsbqPsgXuOlKa+5RG33xyItT1vTze
8gJCVQd+D+LDCnKTs6MRd3Mo4o2WDbc+YPPp3nvBp2zGDK1+baDJCHWAQAPiS77Z
fVLRuYkCgYEA/nWUdZIEN7gcgF+oqGrcjGiMr3m2TIOQ2tnVBpxtw8BCPOKXBkK7
qefC2vD9aPUlbYS3EPvYOuammXDEEHhlNIDEKLE8EVqh90GU6W6FN2a1GUK15l1d
0QeqBPSTeFro1MW4eXmI1a4UktLC3VxiJxgLI/qAGnx99KTy2cVlSxkCgYEA04Ql
6gvZro3l1akWJJGexM7l7cB5PsGnuOzh6r8zmwehRTVAm0gWuaPkaU6qDl3HDkei
pig3M/PH5Hj//IYIso4EVF6XghO5x9pq7C/lE+hOiiwAju3SwBs7GAzWKv04Momu
MnD1uSRhttkMZQThrts+rgV0KU3a7r1Kk7LZ5csCgYEAyLcYntDJ0OXCXaSXFhoM
1BhX+MZp/Nq+tVKkTW2wy3rpBLu7Yy3ad8AfnLIBQfw1RLkt6hCt1HBBs8EWduNw
+UQk9vAusIWsQqwReTw7iqLScRWFBCxbp1mDTBtcA9C53bQEupUaUWraQaJMIW4Q
4kN97ihXSg0vEX3XLd4d82kCgYEAp5tj396cFDHlGjXukfPCd/nrQUbvzMbv/R3Y
t4fjgMm/BXR5SZMKTviMGtZ28wNkpPAm9ruPYt+eWnF3h8c+RR88Vw7NyAmRgciW
Sap6QBgphFvx5VCXXBs37IrfexlE2uc23kmcraUiuR2tMK95lnGtbYBs1/4VqnDd
E8T53ZkCgYEAl+ZcA1jXg2I96C36oMWf4rgfcRfQqinxb53INQJ+7oMiPdMFyp1n
VX2iObQ8OsVTLSZwK1T4+BTMuWfqTVuZh2Wgs7LoX4Uz9/uqHRuAktjjWq4plXjz
0AnF2c9tVcGI/L7BXp08z6lK3P6lxEwLKKMx6DIuWC8RCSHCiKasxoA=
-----END RSA PRIVATE KEY-----"#;

const INITIAL_MODULUS: &str = "rXMZzRpkHwtdgWw-vPxg8LKx71TV9jIqaLp3v1vZAGOf-0U1GZwbztbax5t0n2x-uuK2sT3FZXe6Tgx8VIG4d33VxSc_KY3Mc4H4idhj_F24asrUq72wOZMQY7lthi2pLKdFB8j9zjg9TBvlywxZGeg2MyJ5iBAho0h4FdxCuoOe7IZhzmuoQwIt--SDjQPNz4WiHLAEQUkomCOKEUWAtCuh-M2m6Djd8sQ0nyc1VzDad4IWDOL00WRsgRJ0up0LBL3FFaaIYzOTtyePhaJHxnpdsCTTTe7Qy7YGXcA8jHLtz-PZiImAd_6sR_f10jp8lhIqegcSLT0xvHgsSln5Xw";
const ROTATED_MODULUS: &str = "0j5DrRWu4jhpYjsdslMmOlJN_WMnH4tfd8DYL8XUnd0E7gvfp9IkeUwRoErNYLIDsM5am4COpkzOTelqlrzpIpXJw6d0sn8kzS-N3_GL5rITm2yYnY6X4nIjEgxs7fQaSabN8r8saCeHLMOipzkbsYccK1wyWAj3bHjDbIBpThHV5eVpRHOBjf_epmVQdL6tP58Gz0iVWcbWcXdWpCIWMcOMXR6kAtNOOhBpgbHLerqosteBITekOpxe0Up53gREkLZz8Yb7G9BtbiYpaGRWQx-H3VdLwJhvD80RK64xV39oFpMf8jvIzd4aNP9U6EGfuPbAZjVLOmUiNnqyLbDp0w";

#[test]
fn e2e_access_human_service_and_jwks_rotation_gate_management() -> TestResult {
    let fixture = JwksFixture::start()?;
    let temp = tempfile::tempdir()?;
    let config_path = write_server_config(temp.path(), &fixture)?;
    let mut server = ServerProcess::start(&config_path)?;
    let mut failures = Vec::new();
    let now = unix_seconds();
    let mut access_positive = false;
    let mut secrets = Vec::new();
    let mut unauthorized_response = None;
    for case in incident_cases() {
        let material = request_material_for_case(case, &fixture, now)?;
        secrets.extend(material.secret_values.iter().cloned());
        if case.concurrent_group == Some("unknown-kid-singleflight") {
            let before = fixture.request_count();
            if access_positive {
                fixture.rotate();
                fixture.hold_responses()?;
            }
            let mut public_gate = PublicArrivalGate::start(&server.base_url, 4)?;
            let mut workers = Vec::new();
            for _ in 0..4 {
                let base_url = public_gate.base_url.clone();
                let headers = material.wire_headers.clone();
                workers.push(thread::spawn(move || {
                    raw_http_request_with_incident_headers(
                        &base_url,
                        case.method,
                        case.path,
                        &headers,
                    )
                }));
            }
            if !public_gate.wait_for_arrivals(4)? {
                failures.push(
                    "four public rotated-kid requests did not reach the arrival latch".to_owned(),
                );
            }
            public_gate.release()?;
            if !public_gate.wait_for_forwarded(4)? {
                failures.push(
                    "four public rotated-kid requests were not forwarded together".to_owned(),
                );
            }
            if access_positive {
                if !fixture.wait_for_requests(before + 1, JWKS_BARRIER_TIMEOUT)? {
                    failures.push(
                        "four rotated-kid requests reached the public barrier but no JWKS refresh arrived"
                            .to_owned(),
                    );
                }
                fixture.release_responses()?;
            }
            for worker in workers {
                let raw = worker
                    .join()
                    .map_err(|_| io::Error::other("Access request worker panicked"))??;
                assert_response_secret_free(&raw.response, &material.secret_values)?;
                let response = parse_http_response(&raw.response)?;
                check_incident_contract(case.slot, case.contract, &response, &mut failures);
            }
            if access_positive && fixture.request_count().saturating_sub(before) != 1 {
                failures.push(
                    "four concurrent rotated-kid requests did not share one JWKS refresh"
                        .to_owned(),
                );
            }
            public_gate.finish()?;
            continue;
        }

        if case.concurrent_group == Some("unknown-kid-fail-closed") {
            fixture.set_failure(true);
        }
        let before = fixture.request_count();
        let raw = raw_http_request_with_incident_headers(
            &server.base_url,
            case.method,
            case.path,
            &material.wire_headers,
        )?;
        assert_response_secret_free(&raw.response, &material.secret_values)?;
        let response = parse_http_response(&raw.response)?;
        check_uniform_unauthorized(
            case.slot,
            case.contract,
            &response,
            &mut unauthorized_response,
            &mut failures,
        )?;
        let failures_before = failures.len();
        check_incident_contract(case.slot, case.contract, &response, &mut failures);
        if case.slot == "human-valid" {
            access_positive = failures.len() == failures_before;
        }
        if access_positive
            && case.concurrent_group == Some("unknown-kid-fail-closed")
            && fixture.request_count().saturating_sub(before) != 1
        {
            failures.push("unavailable JWKS did not produce exactly one failed refresh".to_owned());
        }
        fixture.set_failure(false);
    }

    // Endpoint-contact authorization is added in this same scenario after the
    // public Endpoint catalog exists; this phase deliberately uses no mock or
    // hidden Endpoint shortcut.
    if !access_positive && fixture.request_count() != 0 {
        failures.push("empty-router failure unexpectedly contacted JWKS".to_owned());
    }

    let capture = server.stop()?;
    let forbidden = IDENTITY_MARKERS;
    scan_bytes("Server stdout", &capture.stdout, forbidden, &mut failures);
    scan_bytes("Server stderr", &capture.stderr, forbidden, &mut failures);
    scan_tree(temp.path(), forbidden, &mut failures)?;
    for secret in &secrets {
        scan_dynamic_bytes(
            "Server stdout",
            &capture.stdout,
            &secret.value,
            &mut failures,
        );
        scan_dynamic_bytes(
            "Server stderr",
            &capture.stderr,
            &secret.value,
            &mut failures,
        );
        scan_tree_dynamic(temp.path(), &secret.value, &mut failures)?;
    }
    scan_static_secret_material(temp.path(), &capture, &mut failures)?;

    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("Access ingress E2E failures: {}", failures.join("; ")).into())
    }
}

#[test]
fn e2e_system_and_endpoint_catalog_bootstrap_through_access() -> TestResult {
    let jwks = JwksFixture::start()?;
    let temp = tempfile::tempdir()?;
    let endpoint_root = temp.path().join("endpoint");
    let endpoint_config = write_catalog_endpoint_config(&endpoint_root)?;
    let mut endpoint = ServerProcess::start_endpoint(&endpoint_config)?;
    let endpoint_identity = catalog_endpoint_identity(&endpoint.base_url)?;
    let endpoint_id = endpoint_identity["endpoint_id"]
        .as_str()
        .ok_or_else(|| io::Error::other("real Endpoint identity omitted endpoint_id"))?
        .to_owned();
    let mut endpoint_proxy = CountingProxy::start(&endpoint.base_url)?;

    let server_root = temp.path().join("server");
    fs::create_dir(&server_root)?;
    let server_config = write_server_config(&server_root, &jwks)?;
    let mut server = ServerProcess::start(&server_config)?;
    let now = unix_seconds();
    let human_assertion = signed_token(
        INITIAL_PRIVATE_KEY,
        JWKS_INITIAL_KID,
        actor_claims(
            &jwks.issuer(),
            HUMAN_SUB,
            None,
            HUMAN_EMAIL,
            "app",
            now + 300,
        ),
    )?;
    let service_assertion = signed_token(
        INITIAL_PRIVATE_KEY,
        JWKS_INITIAL_KID,
        actor_claims(
            &jwks.issuer(),
            "",
            Some(SERVICE_NAME),
            "service@example.invalid",
            "app",
            now + 300,
        ),
    )?;
    let create_body = json!({
        "label": CATALOG_ENDPOINT_LABEL,
        "base_url": endpoint_proxy.base_url,
        "control_auth": {
            "kind": "bearer",
            "secret": CATALOG_CONTROLLER_SECRET
        }
    });
    let create_bytes = serde_json::to_vec(&create_body)?;
    let forbidden_public = [
        human_assertion.as_str(),
        service_assertion.as_str(),
        CATALOG_CONTROLLER_SECRET,
        CATALOG_DIRECT_SUBJECT,
        HUMAN_SUB,
        SERVICE_NAME,
        HUMAN_EMAIL,
        endpoint_proxy.base_url.as_str(),
    ];

    let scenario_result = (|| -> TestResult {
        let system = catalog_request(
            &server.base_url,
            "GET",
            "/v1/system",
            &human_assertion,
            None,
            None,
            &forbidden_public,
        )?;
        let mut system_failures = Vec::new();
        check_incident_contract(
            "catalog bootstrap system barrier",
            ContractKind::System,
            &system,
            &mut system_failures,
        );
        if !system_failures.is_empty() {
            return Err(io::Error::other(format!(
                "catalog bootstrap is pending the Access/system positive barrier: {}",
                system_failures.join("; ")
            ))
            .into());
        }
        if !jwks.wait_for_requests(1, JWKS_BARRIER_TIMEOUT)? {
            return Err(io::Error::other(
                "catalog bootstrap system request did not reach the configured JWKS fixture",
            )
            .into());
        }

        let before_unauthorized = endpoint_proxy.request_count();
        let unauthorized = catalog_request(
            &server.base_url,
            "POST",
            "/v1/endpoints",
            "malformed-access-assertion",
            Some("catalog-unauthorized-create"),
            Some(&create_bytes),
            &forbidden_public,
        )?;
        assert_catalog_safe_unauthorized(&unauthorized)?;
        if endpoint_proxy.request_count() != before_unauthorized {
            return Err(io::Error::other(
                "invalid Access assertion contacted the real Endpoint before rejection",
            )
            .into());
        }

        let initial_list = catalog_request(
            &server.base_url,
            "GET",
            "/v1/endpoints",
            &human_assertion,
            None,
            None,
            &forbidden_public,
        )?;
        assert_endpoint_list("initial Endpoint list", &initial_list, None)?;

        let create = catalog_request(
            &server.base_url,
            "POST",
            "/v1/endpoints",
            &human_assertion,
            Some("catalog-bootstrap-endpoint"),
            Some(&create_bytes),
            &forbidden_public,
        )?;
        if create.status != 201 {
            return Err(io::Error::other(format!(
                "catalog bootstrap endpoint create expected HTTP 201 after the Access barrier, got {}",
                create.status
            ))
            .into());
        }
        let created = serde_json::from_slice::<Value>(&create.body)?;
        assert_endpoint_record("created Endpoint", &created, &endpoint_id)?;
        if !endpoint_proxy.wait_for_requests(1, JWKS_BARRIER_TIMEOUT)? {
            return Err(io::Error::other(
                "catalog create returned without contacting the real Endpoint",
            )
            .into());
        }

        let contacts_after_create = endpoint_proxy.request_count();
        let replay = catalog_request(
            &server.base_url,
            "POST",
            "/v1/endpoints",
            &human_assertion,
            Some("catalog-bootstrap-endpoint"),
            Some(&create_bytes),
            &forbidden_public,
        )?;
        if replay.status != 201 || replay.body != create.body {
            return Err(io::Error::other(
                "same-key Endpoint bootstrap did not replay the exact status and body",
            )
            .into());
        }
        if endpoint_proxy.request_count() != contacts_after_create {
            return Err(io::Error::other(
                "same-key Endpoint bootstrap replay performed another Endpoint probe",
            )
            .into());
        }

        let human_list = catalog_request(
            &server.base_url,
            "GET",
            "/v1/endpoints",
            &human_assertion,
            None,
            None,
            &forbidden_public,
        )?;
        assert_endpoint_list("human Endpoint list", &human_list, Some(&endpoint_id))?;
        let service_list = catalog_request(
            &server.base_url,
            "GET",
            "/v1/endpoints",
            &service_assertion,
            None,
            None,
            &forbidden_public,
        )?;
        assert_endpoint_list("service Endpoint list", &service_list, Some(&endpoint_id))?;

        let read = catalog_request(
            &server.base_url,
            "GET",
            &format!("/v1/endpoints/{endpoint_id}"),
            &service_assertion,
            None,
            None,
            &forbidden_public,
        )?;
        if read.status != 200 {
            return Err(io::Error::other(format!(
                "service actor Endpoint read expected HTTP 200, got {}",
                read.status
            ))
            .into());
        }
        assert_endpoint_record(
            "service actor Endpoint read",
            &serde_json::from_slice(&read.body)?,
            &endpoint_id,
        )
    })();

    let server_capture = server.stop();
    let proxy_stop = endpoint_proxy.finish();
    let endpoint_capture = endpoint.stop();
    let server_capture = server_capture?;
    let endpoint_capture = endpoint_capture?;
    proxy_stop?;
    assert_catalog_capture_safe(
        &server_capture,
        &endpoint_capture,
        &server_root,
        &endpoint_root,
        &[human_assertion, service_assertion],
    )?;
    scenario_result
}

#[test]
#[ignore = "explicit test-only incident recording; never part of the default suite"]
fn e2e_record_access_ingress_initial_404_cassette() -> TestResult {
    if env::var("ZODE_RECORD_ACCESS_CASSETTE").ok().as_deref() != Some("1") {
        return Err(
            io::Error::other("incident recording requires ZODE_RECORD_ACCESS_CASSETTE=1").into(),
        );
    }

    let destination = incident_cassette_path();
    if destination.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "incident cassette already exists and will not be overwritten",
        )
        .into());
    }

    let jwks = JwksFixture::start()?;
    let temp = tempfile::tempdir()?;
    let config_path = write_server_config(temp.path(), &jwks)?;
    let mut server = ServerProcess::start(&config_path)?;
    let quarantine = QuarantineCapture::new()?;
    let now = unix_seconds();
    let mut exchanges = Vec::new();
    let mut secrets = Vec::new();
    let mut sequence = 0_u64;

    for case in incident_cases() {
        let material = request_material_for_case(case, &jwks, now)?;
        secrets.extend(material.secret_values.iter().cloned());
        let request_count = usize::from(case.concurrent_group == Some("unknown-kid-singleflight"))
            .saturating_mul(3)
            .saturating_add(1);
        if case.concurrent_group == Some("unknown-kid-fail-closed") {
            jwks.set_failure(true);
        }
        let mut workers = Vec::new();
        for _ in 0..request_count {
            let base_url = server.base_url.clone();
            let headers = material.wire_headers.clone();
            workers.push(thread::spawn(move || {
                raw_http_request_with_incident_headers(&base_url, case.method, case.path, &headers)
            }));
        }
        for worker in workers {
            let raw = worker
                .join()
                .map_err(|_| io::Error::other("incident request worker panicked"))??;
            quarantine.record(sequence, &raw)?;
            exchanges.push(sanitize_exchange(&raw, sequence, case, &material)?);
            sequence = sequence.saturating_add(1);
        }
        jwks.set_failure(false);
    }

    let capture = server.stop()?;
    let observed_jwks_requests = jwks.request_count();
    if observed_jwks_requests != 0 {
        return Err(
            io::Error::other("initial unmodified Server contacted JWKS unexpectedly").into(),
        );
    }
    let forbidden = IDENTITY_MARKERS;
    let mut failures = Vec::new();
    scan_bytes("Server stdout", &capture.stdout, forbidden, &mut failures);
    scan_bytes("Server stderr", &capture.stderr, forbidden, &mut failures);
    scan_tree(temp.path(), forbidden, &mut failures)?;
    for secret in &secrets {
        scan_dynamic_bytes(
            "Server stdout",
            &capture.stdout,
            &secret.value,
            &mut failures,
        );
        scan_dynamic_bytes(
            "Server stderr",
            &capture.stderr,
            &secret.value,
            &mut failures,
        );
        scan_tree_dynamic(temp.path(), &secret.value, &mut failures)?;
    }
    scan_static_secret_material(temp.path(), &capture, &mut failures)?;
    if !failures.is_empty() {
        return Err(io::Error::other(failures.join("; ")).into());
    }

    let first = exchanges
        .first()
        .ok_or_else(|| io::Error::other("incident recording captured no exchanges"))?;
    let secret_slots = secrets
        .iter()
        .map(|secret| IncidentSecretSlot {
            name: secret.slot.clone(),
            kind: secret.kind.clone(),
            semantic_sha256: secret.semantic_sha256.clone(),
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut cassette = IncidentCassette {
        schema: INCIDENT_CASSETTE_SCHEMA.to_owned(),
        recording_id: INCIDENT_RECORDING_ID.to_owned(),
        source_recording_id: INCIDENT_SOURCE_RECORDING_ID.to_owned(),
        purpose: "Replay the retained first public HTTP 404 with exact synthetic-slot semantics and the reviewed Access admission contract".to_owned(),
        owner: INCIDENT_OWNER.to_owned(),
        boundary: INCIDENT_BOUNDARY.to_owned(),
        secret_slots,
        first_observed_outcome: IncidentFailure {
            sequence: 0,
            status: first.recorded_response.status,
            safe_error: "empty_router_http_404".to_owned(),
            response_fingerprint: first.recorded_response.fingerprint.clone(),
            observed_jwks_requests,
        },
        exchanges,
        envelope_sha256: String::new(),
    };
    cassette.envelope_sha256 = incident_envelope_digest(&cassette)?;
    let restricted = temp
        .path()
        .join("restricted/access-ingress-auth-boundary-complete.json");
    write_new_json(&restricted, &cassette)?;
    let restricted_bytes = fs::read(&restricted)?;
    validate_cassette(&cassette)?;
    scan_fixture_bytes(
        &restricted_bytes,
        &secrets
            .iter()
            .map(|secret| secret.value.clone())
            .collect::<Vec<_>>(),
    )?;
    promote_immutable_cassette(&restricted, &destination)
}

#[test]
fn e2e_replay_access_ingress_initial_404_cassette() -> TestResult {
    let cassette = read_incident_cassette()?;
    validate_cassette(&cassette)?;
    let jwks = JwksFixture::start()?;
    let temp = tempfile::tempdir()?;
    let config_path = write_server_config(temp.path(), &jwks)?;
    let mut server = ServerProcess::start(&config_path)?;
    let now = unix_seconds();
    let mut failures = Vec::new();
    let mut secrets = Vec::new();
    let mut access_positive = false;
    let mut unauthorized_response = None;
    let cases = expanded_incident_cases();
    let mut cursor = 0_usize;
    while cursor < cassette.exchanges.len() {
        let exchange = &cassette.exchanges[cursor];
        let case = cases[cursor];
        if case.concurrent_group == Some("unknown-kid-singleflight") {
            let group_end = cursor + 4;
            let group = &cassette.exchanges[cursor..group_end];
            let material = request_material_for_case(case, &jwks, now)?;
            verify_material_matches_recording(
                &material,
                &group[0].request,
                &cassette.secret_slots,
            )?;
            secrets.extend(material.secret_values.iter().cloned());
            let before = jwks.request_count();
            if access_positive {
                jwks.rotate();
                jwks.hold_responses()?;
            }
            let mut public_gate = PublicArrivalGate::start(&server.base_url, group.len())?;
            let mut workers = Vec::new();
            for recorded in group {
                let base_url = public_gate.base_url.clone();
                let headers = material.wire_headers.clone();
                let method = recorded.request.method.clone();
                let path = recorded.request.path.clone();
                workers.push(thread::spawn(move || {
                    raw_http_request_with_incident_headers(&base_url, &method, &path, &headers)
                }));
            }
            if !public_gate.wait_for_arrivals(group.len())? {
                failures.push(
                    "cassette unknown-kid requests missed the public arrival latch".to_owned(),
                );
            }
            public_gate.release()?;
            if !public_gate.wait_for_forwarded(group.len())? {
                failures
                    .push("cassette unknown-kid requests were not forwarded together".to_owned());
            }
            if access_positive {
                if !jwks.wait_for_requests(before + 1, JWKS_BARRIER_TIMEOUT)? {
                    failures.push(
                        "cassette public concurrency barrier produced no JWKS refresh arrival"
                            .to_owned(),
                    );
                }
                jwks.release_responses()?;
            }
            for (recorded, worker) in group.iter().zip(workers) {
                let raw = worker
                    .join()
                    .map_err(|_| io::Error::other("cassette request worker panicked"))??;
                assess_replayed_exchange(
                    recorded,
                    case,
                    &material,
                    &raw,
                    &mut unauthorized_response,
                    &mut failures,
                )?;
            }
            if access_positive && jwks.request_count().saturating_sub(before) != 1 {
                failures.push(
                    "cassette unknown-kid requests did not share exactly one JWKS refresh"
                        .to_owned(),
                );
            }
            public_gate.finish()?;
            cursor = group_end;
            continue;
        }

        let material = request_material_for_case(case, &jwks, now)?;
        verify_material_matches_recording(&material, &exchange.request, &cassette.secret_slots)?;
        secrets.extend(material.secret_values.iter().cloned());
        if case.concurrent_group == Some("unknown-kid-fail-closed") {
            jwks.set_failure(true);
        }
        let before = jwks.request_count();
        let raw = raw_http_request_with_incident_headers(
            &server.base_url,
            &exchange.request.method,
            &exchange.request.path,
            &material.wire_headers,
        )?;
        let contract_met = assess_replayed_exchange(
            exchange,
            case,
            &material,
            &raw,
            &mut unauthorized_response,
            &mut failures,
        )?;
        if case.slot == "human-valid" {
            access_positive = contract_met;
        }
        if access_positive
            && case.concurrent_group == Some("unknown-kid-fail-closed")
            && jwks.request_count().saturating_sub(before) != 1
        {
            failures.push("cassette fail-closed case did not perform one JWKS attempt".to_owned());
        }
        jwks.set_failure(false);
        cursor += 1;
    }

    let capture = server.stop()?;
    let forbidden = IDENTITY_MARKERS;
    scan_bytes("Server stdout", &capture.stdout, forbidden, &mut failures);
    scan_bytes("Server stderr", &capture.stderr, forbidden, &mut failures);
    scan_tree(temp.path(), forbidden, &mut failures)?;
    for secret in &secrets {
        scan_dynamic_bytes(
            "Server stdout",
            &capture.stdout,
            &secret.value,
            &mut failures,
        );
        scan_dynamic_bytes(
            "Server stderr",
            &capture.stderr,
            &secret.value,
            &mut failures,
        );
        scan_tree_dynamic(temp.path(), &secret.value, &mut failures)?;
    }
    scan_static_secret_material(temp.path(), &capture, &mut failures)?;
    if !access_positive
        && jwks.request_count() != cassette.first_observed_outcome.observed_jwks_requests
    {
        failures.push("unfixed replay did not preserve the zero-JWKS-contact failure".to_owned());
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(failures.join("; ")).into())
    }
}

fn verify_material_matches_recording(
    material: &RequestMaterial,
    request: &IncidentRequest,
    recorded_slots: &[IncidentSecretSlot],
) -> TestResult<()> {
    if material.semantic_headers != request.semantic_headers {
        return Err(io::Error::other(
            "cassette request slots no longer match the exact generated wire request",
        )
        .into());
    }
    for header in &request.semantic_headers {
        let slot = header
            .value
            .strip_prefix("{{")
            .and_then(|value| value.strip_suffix("}}"))
            .ok_or_else(|| io::Error::other("cassette request header is not slot-backed"))?;
        if !material
            .secret_values
            .iter()
            .any(|secret| secret.slot == slot)
        {
            return Err(io::Error::other(
                "cassette request referenced a secret slot the replay did not resolve",
            )
            .into());
        }
    }
    for secret in &material.secret_values {
        let Some(recorded) = recorded_slots.iter().find(|slot| slot.name == secret.slot) else {
            return Err(io::Error::other(
                "replay resolved a secret slot absent from the immutable cassette",
            )
            .into());
        };
        if recorded.kind != secret.kind || recorded.semantic_sha256 != secret.semantic_sha256 {
            return Err(io::Error::other(
                "regenerated Access material did not match the recorded slot semantics",
            )
            .into());
        }
    }
    Ok(())
}

fn assess_replayed_exchange(
    exchange: &IncidentExchange,
    case: IncidentCase,
    material: &RequestMaterial,
    raw: &RawHttpExchange,
    unauthorized_response: &mut Option<IncidentResponse>,
    failures: &mut Vec<String>,
) -> TestResult<bool> {
    let actual_request =
        canonicalize_captured_request(&parse_raw_request(&raw.request)?, case, material)?;
    if actual_request != exchange.request {
        return Err(io::Error::other(
            "actual incoming public request did not match the recorded cassette request",
        )
        .into());
    }
    assert_response_secret_free(&raw.response, &material.secret_values)?;
    let response = parse_http_response(&raw.response)?;
    check_uniform_unauthorized(
        &format!("cassette {}", exchange.slot),
        case.contract,
        &response,
        unauthorized_response,
        failures,
    )?;
    let actual_record = incident_response(&response)?;
    let mut contract_failures = Vec::new();
    check_incident_contract(
        &format!("cassette {}", exchange.slot),
        case.contract,
        &response,
        &mut contract_failures,
    );
    if contract_failures.is_empty() {
        return Ok(true);
    }
    if actual_record.fingerprint != exchange.recorded_response.fingerprint {
        failures.push(format!(
            "cassette {} response matched neither the target contract nor its immutable first-failure fingerprint",
            exchange.slot
        ));
    } else {
        failures.push(format!(
            "cassette {} replayed immutable first failure {} instead of the target contract",
            exchange.slot, exchange.recorded_response.fingerprint
        ));
    }
    failures.extend(contract_failures);
    Ok(false)
}

fn check_incident_contract(
    label: &str,
    contract: ContractKind,
    response: &HttpResponse,
    failures: &mut Vec<String>,
) {
    scan_response(label, response, failures);
    if response.status != contract.status() {
        failures.push(format!(
            "{label}: expected HTTP {}, got {}",
            contract.status(),
            response.status
        ));
        return;
    }
    match contract {
        ContractKind::System => {
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
                _ => failures.push(format!(
                    "{label}: /v1/system body did not match zode.system.v1 server_only contract"
                )),
            }
        }
        ContractKind::SafeUnauthorized => check_safe_unauthorized(label, response, failures),
        ContractKind::NotFound => {}
    }
}

fn check_safe_unauthorized(label: &str, response: &HttpResponse, failures: &mut Vec<String>) {
    let Ok(Value::Object(root)) = serde_json::from_slice::<Value>(&response.body) else {
        failures.push(format!("{label}: HTTP 401 body was not a JSON object"));
        return;
    };
    if root.len() != 1 || !root.contains_key("error") {
        failures.push(format!(
            "{label}: HTTP 401 body was not the safe error envelope"
        ));
        return;
    }
    let Some(Value::Object(error)) = root.get("error") else {
        failures.push(format!("{label}: HTTP 401 error member was malformed"));
        return;
    };
    let exact_keys = error.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if exact_keys != BTreeSet::from(["code", "message", "retryable"])
        || !matches!(error.get("code"), Some(Value::String(code)) if !code.is_empty() && code.len() <= 64)
        || !matches!(error.get("message"), Some(Value::String(message)) if !message.is_empty() && message.len() <= 256)
        || error.get("retryable") != Some(&Value::Bool(false))
    {
        failures.push(format!(
            "{label}: HTTP 401 error envelope was not bounded and neutral"
        ));
    }
    let disclosed_detail = ["code", "message"].iter().any(|field| {
        error
            .get(*field)
            .and_then(Value::as_str)
            .is_some_and(|value| {
                let value = value.to_ascii_lowercase();
                [
                    "jwt",
                    "token",
                    "signature",
                    "issuer",
                    "audience",
                    "claim",
                    "kid",
                    "jwks",
                    "expired",
                    "not before",
                    "nbf",
                    "common_name",
                    "email",
                    "subject",
                    "rsa",
                ]
                .iter()
                .any(|detail| value.contains(detail))
            })
    });
    if disclosed_detail {
        failures.push(format!(
            "{label}: HTTP 401 error disclosed Access verification detail"
        ));
    }
}

fn check_uniform_unauthorized(
    label: &str,
    contract: ContractKind,
    response: &HttpResponse,
    baseline: &mut Option<IncidentResponse>,
    failures: &mut Vec<String>,
) -> TestResult<()> {
    if contract != ContractKind::SafeUnauthorized || response.status != 401 {
        return Ok(());
    }
    let current = incident_response(response)?;
    match baseline {
        Some(expected) if expected != &current => failures.push(format!(
            "{label}: invalid Access inputs did not receive one neutral HTTP 401 response"
        )),
        None => *baseline = Some(current),
        Some(_) => {}
    }
    Ok(())
}

fn assert_response_secret_free(response: &[u8], secrets: &[SecretValue]) -> TestResult<()> {
    for marker in IDENTITY_MARKERS.iter().copied().chain([
        std::str::from_utf8(SUBJECT_KEY).unwrap_or(""),
        "MIIEpAIBAAKCAQEA",
        "MIIEpQIBAAKCAQEA",
    ]) {
        if !marker.is_empty()
            && response
                .windows(marker.len())
                .any(|window| window == marker.as_bytes())
        {
            return Err(io::Error::other(
                "public response contained an Access identity or signing marker",
            )
            .into());
        }
    }
    if secrets.iter().any(|secret| {
        response
            .windows(secret.value.len())
            .any(|window| window == secret.value.as_bytes())
    }) {
        return Err(io::Error::other("public response contained a synthetic secret value").into());
    }
    Ok(())
}

struct QuarantineCapture {
    root: PathBuf,
}

struct PublicArrivalGate {
    address: SocketAddr,
    base_url: String,
    state: Arc<(Mutex<PublicGateState>, Condvar)>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

struct PublicGateState {
    arrived: usize,
    forwarded: usize,
    released: bool,
}

impl PublicArrivalGate {
    fn start(upstream_base_url: &str, expected: usize) -> TestResult<Self> {
        let upstream = Url::parse(upstream_base_url)?;
        let upstream_host = upstream
            .host_str()
            .ok_or_else(|| io::Error::other("Server upstream URL had no host"))?
            .to_owned();
        let upstream_port = upstream
            .port_or_known_default()
            .ok_or_else(|| io::Error::other("Server upstream URL had no port"))?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let state = Arc::new((
            Mutex::new(PublicGateState {
                arrived: 0,
                forwarded: 0,
                released: false,
            }),
            Condvar::new(),
        ));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_state = Arc::clone(&state);
        let thread_stop = Arc::clone(&stop);
        let join = thread::spawn(move || {
            let mut workers = Vec::new();
            while workers.len() < expected && !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let state = Arc::clone(&thread_state);
                        let stop = Arc::clone(&thread_stop);
                        let host = upstream_host.clone();
                        workers.push(thread::spawn(move || {
                            let _ =
                                proxy_public_request(stream, &host, upstream_port, &state, &stop);
                        }));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(POLL_INTERVAL);
                    }
                    Err(_) => break,
                }
            }
            for worker in workers {
                let _ = worker.join();
            }
        });
        Ok(Self {
            address,
            base_url: format!("http://{address}"),
            state,
            stop,
            join: Some(join),
        })
    }

    fn wait_for_arrivals(&self, expected: usize) -> TestResult<bool> {
        self.wait_for_count(expected, |state| state.arrived)
    }

    fn wait_for_forwarded(&self, expected: usize) -> TestResult<bool> {
        self.wait_for_count(expected, |state| state.forwarded)
    }

    fn wait_for_count(
        &self,
        expected: usize,
        value: impl Fn(&PublicGateState) -> usize,
    ) -> TestResult<bool> {
        let deadline = Instant::now() + JWKS_BARRIER_TIMEOUT;
        let (state, changed) = &*self.state;
        let mut state = state
            .lock()
            .map_err(|_| io::Error::other("public request gate lock poisoned"))?;
        while value(&state) < expected {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            let (next, result) = changed
                .wait_timeout(state, remaining)
                .map_err(|_| io::Error::other("public request gate lock poisoned"))?;
            state = next;
            if result.timed_out() && value(&state) < expected {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn release(&self) -> TestResult<()> {
        let (state, changed) = &*self.state;
        let mut state = state
            .lock()
            .map_err(|_| io::Error::other("public request gate lock poisoned"))?;
        if state.released {
            return Err(io::Error::other("public request gate was released more than once").into());
        }
        state.released = true;
        changed.notify_all();
        Ok(())
    }

    fn finish(&mut self) -> TestResult<()> {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        if let Some(join) = self.join.take() {
            join.join()
                .map_err(|_| io::Error::other("public request gate panicked"))?;
        }
        Ok(())
    }
}

impl Drop for PublicArrivalGate {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Ok(mut state) = self.state.0.lock() {
            state.released = true;
            self.state.1.notify_all();
        }
        let _ = TcpStream::connect(self.address);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

struct CountingProxy {
    address: SocketAddr,
    base_url: String,
    requests: Arc<AtomicUsize>,
    changed: Arc<(Mutex<()>, Condvar)>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl CountingProxy {
    fn start(upstream_base_url: &str) -> TestResult<Self> {
        let upstream = Url::parse(upstream_base_url)?;
        let upstream_host = upstream
            .host_str()
            .ok_or_else(|| io::Error::other("Endpoint proxy upstream URL had no host"))?
            .to_owned();
        let upstream_port = upstream
            .port_or_known_default()
            .ok_or_else(|| io::Error::other("Endpoint proxy upstream URL had no port"))?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let requests = Arc::new(AtomicUsize::new(0));
        let changed = Arc::new((Mutex::new(()), Condvar::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_requests = Arc::clone(&requests);
        let thread_changed = Arc::clone(&changed);
        let thread_stop = Arc::clone(&stop);
        let join = thread::spawn(move || {
            let mut workers = Vec::new();
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let host = upstream_host.clone();
                        let requests = Arc::clone(&thread_requests);
                        let changed = Arc::clone(&thread_changed);
                        workers.push(thread::spawn(move || {
                            let _ = proxy_counted_request(
                                stream,
                                &host,
                                upstream_port,
                                &requests,
                                &changed,
                            );
                        }));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(POLL_INTERVAL);
                    }
                    Err(_) => break,
                }
            }
            for worker in workers {
                let _ = worker.join();
            }
        });
        Ok(Self {
            address,
            base_url: format!("http://{address}"),
            requests,
            changed,
            stop,
            join: Some(join),
        })
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::Acquire)
    }

    fn wait_for_requests(&self, minimum: usize, timeout: Duration) -> TestResult<bool> {
        let deadline = Instant::now() + timeout;
        let (gate, changed) = &*self.changed;
        let mut guard = gate
            .lock()
            .map_err(|_| io::Error::other("Endpoint proxy count lock poisoned"))?;
        while self.request_count() < minimum {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            let (next, result) = changed
                .wait_timeout(guard, remaining)
                .map_err(|_| io::Error::other("Endpoint proxy count lock poisoned"))?;
            guard = next;
            if result.timed_out() && self.request_count() < minimum {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn finish(&mut self) -> TestResult<()> {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        if let Some(join) = self.join.take() {
            join.join()
                .map_err(|_| io::Error::other("Endpoint counting proxy panicked"))?;
        }
        Ok(())
    }
}

impl Drop for CountingProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn proxy_counted_request(
    mut client: TcpStream,
    upstream_host: &str,
    upstream_port: u16,
    requests: &AtomicUsize,
    changed: &(Mutex<()>, Condvar),
) -> io::Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    client.set_write_timeout(Some(Duration::from_secs(5)))?;
    let request = read_bounded_http_request(&mut client)?;
    let request = request_with_connection_close(&request)?;
    let mut upstream = TcpStream::connect((upstream_host, upstream_port))?;
    upstream.set_read_timeout(Some(Duration::from_secs(5)))?;
    upstream.set_write_timeout(Some(Duration::from_secs(5)))?;
    upstream.write_all(&request)?;
    requests.fetch_add(1, Ordering::AcqRel);
    changed.1.notify_all();
    let mut response = Vec::new();
    upstream.read_to_end(&mut response)?;
    client.write_all(&response)
}

fn request_with_connection_close(request: &[u8]) -> io::Result<Vec<u8>> {
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "proxy request was incomplete")
        })?;
    let headers = std::str::from_utf8(&request[..header_end]).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy request headers were not UTF-8",
        )
    })?;
    let mut rewritten = String::new();
    for (index, line) in headers.split("\r\n").enumerate() {
        if index > 0 && line.to_ascii_lowercase().starts_with("connection:") {
            continue;
        }
        rewritten.push_str(line);
        rewritten.push_str("\r\n");
    }
    rewritten.push_str("Connection: close\r\n\r\n");
    let mut bytes = rewritten.into_bytes();
    bytes.extend_from_slice(&request[header_end + 4..]);
    Ok(bytes)
}

fn proxy_public_request(
    mut client: TcpStream,
    upstream_host: &str,
    upstream_port: u16,
    state: &(Mutex<PublicGateState>, Condvar),
    stop: &AtomicBool,
) -> io::Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    client.set_write_timeout(Some(Duration::from_secs(5)))?;
    let request = read_bounded_http_request(&mut client)?;
    {
        let (gate, changed) = state;
        let mut state = gate
            .lock()
            .map_err(|_| io::Error::other("public request gate lock poisoned"))?;
        state.arrived = state.arrived.saturating_add(1);
        changed.notify_all();
        while !state.released && !stop.load(Ordering::Acquire) {
            state = changed
                .wait(state)
                .map_err(|_| io::Error::other("public request gate lock poisoned"))?;
        }
    }
    if stop.load(Ordering::Acquire) {
        return Ok(());
    }
    let mut upstream = TcpStream::connect((upstream_host, upstream_port))?;
    upstream.set_read_timeout(Some(Duration::from_secs(5)))?;
    upstream.set_write_timeout(Some(Duration::from_secs(5)))?;
    upstream.write_all(&request)?;
    {
        let (gate, changed) = state;
        let mut state = gate
            .lock()
            .map_err(|_| io::Error::other("public request gate lock poisoned"))?;
        state.forwarded = state.forwarded.saturating_add(1);
        changed.notify_all();
    }
    let mut response = Vec::new();
    upstream.read_to_end(&mut response)?;
    client.write_all(&response)
}

fn read_bounded_http_request(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    const MAX_REQUEST_BYTES: usize = 64 * 1024;
    let mut request = Vec::new();
    let mut chunk = [0_u8; 2048];
    let header_end = loop {
        if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break end;
        }
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "public request gate input ended before headers",
            ));
        }
        request.extend_from_slice(&chunk[..read]);
        if request.len() > MAX_REQUEST_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "public request gate input exceeded its bound",
            ));
        }
    };
    let header_text = std::str::from_utf8(&request[..header_end]).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "public request gate headers were not UTF-8",
        )
    })?;
    let content_length = header_text
        .split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| {
            value.trim().parse::<usize>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "public request gate content length was invalid",
                )
            })
        })
        .transpose()?
        .unwrap_or(0);
    let required = header_end
        .checked_add(4)
        .and_then(|value| value.checked_add(content_length))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "request length overflow"))?;
    if required > MAX_REQUEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "public request gate input exceeded its bound",
        ));
    }
    while request.len() < required {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "public request gate body ended early",
            ));
        }
        request.extend_from_slice(&chunk[..read]);
        if request.len() > MAX_REQUEST_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "public request gate input exceeded its bound",
            ));
        }
    }
    request.truncate(required);
    Ok(request)
}

impl QuarantineCapture {
    fn new() -> TestResult<Self> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target/test-recordings/quarantine")
            .join(format!(
                "{INCIDENT_RECORDING_ID}-{}-{nonce}",
                std::process::id()
            ));
        fs::create_dir_all(&root)?;
        set_restricted_directory_permissions(&root)?;
        Ok(Self { root })
    }

    fn record(&self, sequence: u64, exchange: &RawHttpExchange) -> TestResult<()> {
        write_restricted_new(
            &self.root.join(format!("{sequence:04}.request.http")),
            &exchange.request,
        )?;
        write_restricted_new(
            &self.root.join(format!("{sequence:04}.response.http")),
            &exchange.response,
        )
    }
}

fn write_restricted_new(path: &Path, bytes: &[u8]) -> TestResult<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn set_restricted_directory_permissions(path: &Path) -> TestResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IncidentCase {
    slot: &'static str,
    method: &'static str,
    path: &'static str,
    contract: ContractKind,
    concurrent_group: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContractKind {
    System,
    SafeUnauthorized,
    NotFound,
}

impl ContractKind {
    fn name(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::SafeUnauthorized => "safe_unauthorized",
            Self::NotFound => "not_found",
        }
    }

    fn status(self) -> u16 {
        match self {
            Self::System => 200,
            Self::SafeUnauthorized => 401,
            Self::NotFound => 404,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IncidentCassette {
    schema: String,
    recording_id: String,
    source_recording_id: String,
    purpose: String,
    owner: String,
    boundary: String,
    secret_slots: Vec<IncidentSecretSlot>,
    first_observed_outcome: IncidentFailure,
    exchanges: Vec<IncidentExchange>,
    envelope_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
struct IncidentSecretSlot {
    name: String,
    kind: String,
    semantic_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IncidentFailure {
    sequence: u64,
    status: u16,
    safe_error: String,
    response_fingerprint: String,
    observed_jwks_requests: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IncidentExchange {
    sequence: u64,
    slot: String,
    phase: String,
    concurrent_group: Option<String>,
    request: IncidentRequest,
    recorded_response: IncidentResponse,
    contract: IncidentContract,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct IncidentRequest {
    method: String,
    path: String,
    semantic_headers: Vec<IncidentHeader>,
    semantic_headers_sha256: String,
    raw_body_hex: String,
    canonical_json: Option<Value>,
    body_sha256: String,
    fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct IncidentResponse {
    status: u16,
    semantic_headers: Vec<IncidentHeader>,
    semantic_headers_sha256: String,
    body_hex: String,
    body_sha256: String,
    outcome: String,
    fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IncidentContract {
    status: u16,
    kind: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct IncidentHeader {
    name: String,
    value: String,
}

struct RawHttpExchange {
    request: Vec<u8>,
    response: Vec<u8>,
}

struct RawRequestShape {
    method: String,
    path: String,
    headers: Vec<IncidentHeader>,
    body: Vec<u8>,
}

fn incident_cases() -> Vec<IncidentCase> {
    vec![
        IncidentCase {
            slot: "human-valid",
            method: "GET",
            path: "/v1/system",
            contract: ContractKind::System,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "service-valid",
            method: "GET",
            path: "/v1/system",
            contract: ContractKind::System,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "missing-assertion",
            method: "GET",
            path: "/v1/system",
            contract: ContractKind::SafeUnauthorized,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "duplicate-assertion",
            method: "GET",
            path: "/v1/system",
            contract: ContractKind::SafeUnauthorized,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "malformed-assertion",
            method: "GET",
            path: "/v1/system",
            contract: ContractKind::SafeUnauthorized,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "forged-signature",
            method: "GET",
            path: "/v1/system",
            contract: ContractKind::SafeUnauthorized,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "expired-beyond-skew",
            method: "GET",
            path: "/v1/system",
            contract: ContractKind::SafeUnauthorized,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "future-nbf-beyond-skew",
            method: "GET",
            path: "/v1/system",
            contract: ContractKind::SafeUnauthorized,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "wrong-issuer",
            method: "GET",
            path: "/v1/system",
            contract: ContractKind::SafeUnauthorized,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "missing-issuer",
            method: "GET",
            path: "/v1/system",
            contract: ContractKind::SafeUnauthorized,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "non-string-issuer",
            method: "GET",
            path: "/v1/system",
            contract: ContractKind::SafeUnauthorized,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "wrong-audience",
            method: "GET",
            path: "/v1/system",
            contract: ContractKind::SafeUnauthorized,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "missing-audience",
            method: "GET",
            path: "/v1/system",
            contract: ContractKind::SafeUnauthorized,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "non-string-audience",
            method: "GET",
            path: "/v1/system",
            contract: ContractKind::SafeUnauthorized,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "unsupported-algorithm",
            method: "GET",
            path: "/v1/system",
            contract: ContractKind::SafeUnauthorized,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "missing-kid",
            method: "GET",
            path: "/v1/system",
            contract: ContractKind::SafeUnauthorized,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "missing-type",
            method: "GET",
            path: "/v1/system",
            contract: ContractKind::SafeUnauthorized,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "wrong-type",
            method: "GET",
            path: "/v1/system",
            contract: ContractKind::SafeUnauthorized,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "missing-exp",
            method: "GET",
            path: "/v1/system",
            contract: ContractKind::SafeUnauthorized,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "non-numeric-exp",
            method: "GET",
            path: "/v1/system",
            contract: ContractKind::SafeUnauthorized,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "non-numeric-nbf",
            method: "GET",
            path: "/v1/system",
            contract: ContractKind::SafeUnauthorized,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "missing-subject",
            method: "GET",
            path: "/v1/system",
            contract: ContractKind::SafeUnauthorized,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "ambiguous-actor",
            method: "GET",
            path: "/v1/system",
            contract: ContractKind::SafeUnauthorized,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "empty-actor",
            method: "GET",
            path: "/v1/system",
            contract: ContractKind::SafeUnauthorized,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "non-string-subject",
            method: "GET",
            path: "/v1/system",
            contract: ContractKind::SafeUnauthorized,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "custom-identity-headers",
            method: "GET",
            path: "/v1/system",
            contract: ContractKind::SafeUnauthorized,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "unknown-kid-singleflight",
            method: "GET",
            path: "/v1/system",
            contract: ContractKind::System,
            concurrent_group: Some("unknown-kid-singleflight"),
        },
        IncidentCase {
            slot: "unknown-kid-fail-closed",
            method: "GET",
            path: "/v1/system",
            contract: ContractKind::SafeUnauthorized,
            concurrent_group: Some("unknown-kid-fail-closed"),
        },
        IncidentCase {
            slot: "no-user-route-login",
            method: "GET",
            path: "/v1/login",
            contract: ContractKind::NotFound,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "no-user-route-logout",
            method: "POST",
            path: "/v1/logout",
            contract: ContractKind::NotFound,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "no-user-route-users",
            method: "GET",
            path: "/v1/users",
            contract: ContractKind::NotFound,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "no-user-route-workspaces",
            method: "GET",
            path: "/v1/workspaces",
            contract: ContractKind::NotFound,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "no-user-route-roles",
            method: "GET",
            path: "/v1/roles",
            contract: ContractKind::NotFound,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "no-user-route-grants",
            method: "GET",
            path: "/v1/grants",
            contract: ContractKind::NotFound,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "no-user-route-current-user",
            method: "GET",
            path: "/v1/current-user",
            contract: ContractKind::NotFound,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "no-user-route-principal",
            method: "GET",
            path: "/v1/principal",
            contract: ContractKind::NotFound,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "no-user-route-invite",
            method: "POST",
            path: "/v1/invite",
            contract: ContractKind::NotFound,
            concurrent_group: None,
        },
        IncidentCase {
            slot: "no-user-route-account",
            method: "GET",
            path: "/v1/account",
            contract: ContractKind::NotFound,
            concurrent_group: None,
        },
    ]
}

fn incident_cassette_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(INCIDENT_CASSETTE_PATH)
}

fn token_for_slot(slot: &str, fixture: &JwksFixture, now: i64) -> TestResult<Option<String>> {
    let issuer = fixture.issuer();
    let claims = |sub: &str, common_name: Option<&str>, email: &str, token_type: &str| {
        actor_claims(&issuer, sub, common_name, email, token_type, now + 300)
    };
    let token = match slot {
        "human-valid" => Some(signed_token(
            INITIAL_PRIVATE_KEY,
            JWKS_INITIAL_KID,
            claims(HUMAN_SUB, None, HUMAN_EMAIL, "app"),
        )?),
        "service-valid" => Some(signed_token(
            INITIAL_PRIVATE_KEY,
            JWKS_INITIAL_KID,
            claims("", Some(SERVICE_NAME), "", "app"),
        )?),
        "missing-assertion" => None,
        "duplicate-assertion" => Some(signed_token(
            INITIAL_PRIVATE_KEY,
            JWKS_INITIAL_KID,
            claims(HUMAN_SUB, None, HUMAN_EMAIL, "app"),
        )?),
        "malformed-assertion" => Some("not-a-jwt".to_owned()),
        "forged-signature" => Some(signed_token(
            ROTATED_PRIVATE_KEY,
            JWKS_INITIAL_KID,
            claims("forged-human", None, "forged@example.invalid", "app"),
        )?),
        "expired-beyond-skew" => Some(signed_token(
            INITIAL_PRIVATE_KEY,
            JWKS_INITIAL_KID,
            actor_claims_with_times(
                &issuer,
                "expired-human",
                None,
                "expired@example.invalid",
                "app",
                now - 3600,
                now - 3660,
            ),
        )?),
        "future-nbf-beyond-skew" => Some(signed_token(
            INITIAL_PRIVATE_KEY,
            JWKS_INITIAL_KID,
            actor_claims_with_times(
                &issuer,
                "future-nbf-human",
                None,
                "future-nbf@example.invalid",
                "app",
                now + 3600,
                now + 3600,
            ),
        )?),
        "wrong-issuer" => Some(signed_token(
            INITIAL_PRIVATE_KEY,
            JWKS_INITIAL_KID,
            actor_claims(
                "http://wrong-issuer.invalid/",
                "wrong-issuer-human",
                None,
                "wrong-issuer@example.invalid",
                "app",
                now + 300,
            ),
        )?),
        "missing-issuer" => {
            let mut value = claims(HUMAN_SUB, None, HUMAN_EMAIL, "app");
            claim_object(&mut value)?.remove("iss");
            Some(signed_token(INITIAL_PRIVATE_KEY, JWKS_INITIAL_KID, value)?)
        }
        "non-string-issuer" => {
            let mut value = claims(HUMAN_SUB, None, HUMAN_EMAIL, "app");
            claim_object(&mut value)?.insert("iss".into(), json!(42));
            Some(signed_token(INITIAL_PRIVATE_KEY, JWKS_INITIAL_KID, value)?)
        }
        "wrong-audience" => Some(signed_token(
            INITIAL_PRIVATE_KEY,
            JWKS_INITIAL_KID,
            actor_claims_with_audience(
                &issuer,
                "wrong-audience-human",
                None,
                "wrong-audience@example.invalid",
                "other-audience",
                "app",
                now + 300,
            ),
        )?),
        "missing-audience" => {
            let mut value = claims(HUMAN_SUB, None, HUMAN_EMAIL, "app");
            claim_object(&mut value)?.remove("aud");
            Some(signed_token(INITIAL_PRIVATE_KEY, JWKS_INITIAL_KID, value)?)
        }
        "non-string-audience" => {
            let mut value = claims(HUMAN_SUB, None, HUMAN_EMAIL, "app");
            claim_object(&mut value)?.insert("aud".into(), json!(42));
            Some(signed_token(INITIAL_PRIVATE_KEY, JWKS_INITIAL_KID, value)?)
        }
        "unsupported-algorithm" => Some(signed_hs256_token(
            "synthetic-access-test-signing-slot",
            claims(
                "unsupported-alg-human",
                None,
                "unsupported-alg@example.invalid",
                "app",
            ),
        )?),
        "missing-kid" => Some(signed_token_without_kid(
            INITIAL_PRIVATE_KEY,
            claims(
                "missing-kid-human",
                None,
                "missing-kid@example.invalid",
                "app",
            ),
        )?),
        "missing-type" => {
            let mut value = claims(
                "missing-type-human",
                None,
                "missing-type@example.invalid",
                "app",
            );
            value
                .as_object_mut()
                .ok_or_else(|| io::Error::other("claims object missing"))?
                .remove("type");
            Some(signed_token(INITIAL_PRIVATE_KEY, JWKS_INITIAL_KID, value)?)
        }
        "missing-subject" => {
            let mut value = claims(
                "missing-subject-human",
                None,
                "missing-subject@example.invalid",
                "app",
            );
            value
                .as_object_mut()
                .ok_or_else(|| io::Error::other("claims object missing"))?
                .remove("sub");
            Some(signed_token(INITIAL_PRIVATE_KEY, JWKS_INITIAL_KID, value)?)
        }
        "wrong-type" => Some(signed_token(
            INITIAL_PRIVATE_KEY,
            JWKS_INITIAL_KID,
            claims(
                "wrong-type-human",
                None,
                "wrong-type@example.invalid",
                "not-app",
            ),
        )?),
        "missing-exp" => {
            let mut value = claims(HUMAN_SUB, None, HUMAN_EMAIL, "app");
            claim_object(&mut value)?.remove("exp");
            Some(signed_token(INITIAL_PRIVATE_KEY, JWKS_INITIAL_KID, value)?)
        }
        "non-numeric-exp" => {
            let mut value = claims(HUMAN_SUB, None, HUMAN_EMAIL, "app");
            claim_object(&mut value)?.insert("exp".into(), json!("tomorrow"));
            Some(signed_token(INITIAL_PRIVATE_KEY, JWKS_INITIAL_KID, value)?)
        }
        "non-numeric-nbf" => {
            let mut value = claims(HUMAN_SUB, None, HUMAN_EMAIL, "app");
            claim_object(&mut value)?.insert("nbf".into(), json!("later"));
            Some(signed_token(INITIAL_PRIVATE_KEY, JWKS_INITIAL_KID, value)?)
        }
        "ambiguous-actor" => Some(signed_token(
            INITIAL_PRIVATE_KEY,
            JWKS_INITIAL_KID,
            claims(
                "ambiguous-human",
                Some("ambiguous-service"),
                "ambiguous@example.invalid",
                "app",
            ),
        )?),
        "empty-actor" => Some(signed_token(
            INITIAL_PRIVATE_KEY,
            JWKS_INITIAL_KID,
            claims("", None, "empty@example.invalid", "app"),
        )?),
        "non-string-subject" => Some(signed_token(
            INITIAL_PRIVATE_KEY,
            JWKS_INITIAL_KID,
            non_string_subject_claims(&issuer, now + 300),
        )?),
        "custom-identity-headers" => None,
        "unknown-kid-singleflight" => Some(signed_token(
            ROTATED_PRIVATE_KEY,
            JWKS_ROTATED_KID,
            claims(
                "unknown-kid-human",
                None,
                "unknown-kid@example.invalid",
                "app",
            ),
        )?),
        "unknown-kid-fail-closed" => Some(signed_token(
            INITIAL_PRIVATE_KEY,
            "unknown-kid-fail-closed",
            claims(
                "unknown-fail-human",
                None,
                "unknown-fail@example.invalid",
                "app",
            ),
        )?),
        slot if slot.starts_with("no-user-route-") => Some(signed_token(
            INITIAL_PRIVATE_KEY,
            JWKS_INITIAL_KID,
            claims(HUMAN_SUB, None, HUMAN_EMAIL, "app"),
        )?),
        other => {
            return Err(io::Error::other(format!("unknown Access cassette slot: {other}")).into())
        }
    };
    Ok(token)
}

fn claim_object(value: &mut Value) -> TestResult<&mut Map<String, Value>> {
    value
        .as_object_mut()
        .ok_or_else(|| io::Error::other("claims object missing").into())
}

struct RequestMaterial {
    wire_headers: Vec<IncidentHeader>,
    semantic_headers: Vec<IncidentHeader>,
    secret_values: Vec<SecretValue>,
}

#[derive(Clone)]
struct SecretValue {
    slot: String,
    value: String,
    kind: String,
    semantic_sha256: String,
}

fn request_material_for_case(
    case: IncidentCase,
    fixture: &JwksFixture,
    now: i64,
) -> TestResult<RequestMaterial> {
    let mut wire_headers = Vec::new();
    let mut semantic_headers = Vec::new();
    let mut secret_values = Vec::new();
    match case.slot {
        "missing-assertion" => {}
        "duplicate-assertion" => {
            let first = token_for_slot("human-valid", fixture, now)?
                .ok_or_else(|| io::Error::other("duplicate assertion first token missing"))?;
            let second = token_for_slot("service-valid", fixture, now)?
                .ok_or_else(|| io::Error::other("duplicate assertion second token missing"))?;
            add_secret_header(
                &mut wire_headers,
                &mut semantic_headers,
                &mut secret_values,
                "cf-access-jwt-assertion",
                "SLOT_ACCESS_ASSERTION_DUPLICATE_A",
                first,
            );
            add_secret_header(
                &mut wire_headers,
                &mut semantic_headers,
                &mut secret_values,
                "cf-access-jwt-assertion",
                "SLOT_ACCESS_ASSERTION_DUPLICATE_B",
                second,
            );
        }
        "custom-identity-headers" => {
            for (name, slot, value) in [
                (
                    "cf-authorization",
                    "SLOT_CUSTOM_CF_AUTHORIZATION",
                    "custom-access-cookie-identity-marker",
                ),
                (
                    "cf-access-authenticated-user-email",
                    "SLOT_CUSTOM_ACCESS_EMAIL",
                    "custom-header-email@example.invalid",
                ),
                (
                    "x-zode-subject",
                    "SLOT_CUSTOM_ZODE_SUBJECT",
                    "custom-header-subject-marker",
                ),
            ] {
                add_secret_header(
                    &mut wire_headers,
                    &mut semantic_headers,
                    &mut secret_values,
                    name,
                    slot,
                    value.to_owned(),
                );
            }
        }
        _ => {
            if let Some(token) = token_for_slot(case.slot, fixture, now)? {
                let slot = format!("SLOT_ACCESS_ASSERTION_{}", slot_suffix(case.slot));
                add_secret_header(
                    &mut wire_headers,
                    &mut semantic_headers,
                    &mut secret_values,
                    "cf-access-jwt-assertion",
                    &slot,
                    token,
                );
            }
        }
    }
    for secret in &mut secret_values {
        let (kind, semantic_sha256) =
            secret_slot_semantics(&secret.slot, &secret.value, fixture, now)?;
        secret.kind = kind;
        secret.semantic_sha256 = semantic_sha256;
    }
    Ok(RequestMaterial {
        wire_headers,
        semantic_headers,
        secret_values,
    })
}

fn add_secret_header(
    wire_headers: &mut Vec<IncidentHeader>,
    semantic_headers: &mut Vec<IncidentHeader>,
    secret_values: &mut Vec<SecretValue>,
    name: &str,
    slot: &str,
    value: String,
) {
    wire_headers.push(IncidentHeader {
        name: name.to_owned(),
        value: value.clone(),
    });
    semantic_headers.push(IncidentHeader {
        name: name.to_owned(),
        value: format!("{{{{{slot}}}}}"),
    });
    secret_values.push(SecretValue {
        slot: slot.to_owned(),
        value,
        kind: String::new(),
        semantic_sha256: String::new(),
    });
}

fn slot_suffix(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn secret_slot_semantics(
    slot: &str,
    value: &str,
    fixture: &JwksFixture,
    now: i64,
) -> TestResult<(String, String)> {
    if slot.starts_with("SLOT_CUSTOM_") {
        let semantic = json!({
            "kind": "custom_identity_header",
            "slot": slot,
        });
        return Ok((
            "custom_identity_header".to_owned(),
            sha256_hex(&serde_json::to_vec(&semantic)?),
        ));
    }
    if value == "not-a-jwt" {
        let semantic = json!({
            "kind": "malformed_access_assertion",
            "shape": "not_jwt",
        });
        return Ok((
            "access_assertion".to_owned(),
            sha256_hex(&serde_json::to_vec(&semantic)?),
        ));
    }

    let mut segments = value.split('.');
    let encoded_header = segments
        .next()
        .ok_or_else(|| io::Error::other("Access assertion header segment missing"))?;
    let encoded_claims = segments
        .next()
        .ok_or_else(|| io::Error::other("Access assertion claims segment missing"))?;
    let signature = segments
        .next()
        .filter(|signature| !signature.is_empty())
        .ok_or_else(|| io::Error::other("Access assertion signature segment missing"))?;
    if segments.next().is_some() {
        return Err(io::Error::other("Access assertion had extra segments").into());
    }
    let header: Value = serde_json::from_slice(&base64url_decode(encoded_header)?)?;
    let mut claims: Value = serde_json::from_slice(&base64url_decode(encoded_claims)?)?;
    sanitize_access_claims(&mut claims, fixture, now)?;
    let semantic = json!({
        "kind": "access_assertion",
        "header": header,
        "claims": claims,
        "signature_role": access_signature_role(value),
        "signature_present": !signature.is_empty(),
    });
    Ok((
        "access_assertion".to_owned(),
        sha256_hex(&serde_json::to_vec(&semantic)?),
    ))
}

fn sanitize_access_claims(claims: &mut Value, fixture: &JwksFixture, now: i64) -> TestResult<()> {
    let claims = claims
        .as_object_mut()
        .ok_or_else(|| io::Error::other("Access assertion claims were not an object"))?;
    let configured_issuer = fixture.issuer();
    if let Some(issuer) = claims.get_mut("iss") {
        if issuer.as_str() == Some(configured_issuer.as_str()) {
            *issuer = Value::String("{{SLOT_CONFIGURED_ISSUER}}".to_owned());
        } else if issuer.is_string() {
            *issuer = Value::String("{{SLOT_WRONG_ISSUER}}".to_owned());
        }
    }
    if let Some(audience) = claims.get_mut("aud") {
        sanitize_audience(audience);
    }
    for identity in ["sub", "common_name", "email"] {
        if let Some(value) = claims.get_mut(identity) {
            if value.as_str().is_some_and(|value| !value.is_empty()) {
                *value = Value::String(format!("{{{{SLOT_{}}}}}", identity.to_ascii_uppercase()));
            }
        }
    }
    if let Some(expiry) = claims.get_mut("exp") {
        sanitize_time_claim(expiry, "exp", now);
    }
    if let Some(not_before) = claims.get_mut("nbf") {
        sanitize_time_claim(not_before, "nbf", now);
    }
    Ok(())
}

fn sanitize_audience(audience: &mut Value) {
    match audience {
        Value::String(value) => {
            *value = if value == AUDIENCE {
                "{{SLOT_CONFIGURED_AUDIENCE}}".to_owned()
            } else {
                "{{SLOT_WRONG_AUDIENCE}}".to_owned()
            };
        }
        Value::Array(values) => {
            for value in values {
                sanitize_audience(value);
            }
        }
        _ => {}
    }
}

fn sanitize_time_claim(value: &mut Value, claim: &str, now: i64) {
    let Some(number) = value.as_i64() else {
        if value.is_string() {
            *value = Value::String(format!(
                "{{{{SLOT_NON_NUMERIC_{}}}}}",
                claim.to_ascii_uppercase()
            ));
        }
        return;
    };
    let classification = match claim {
        "exp" if number < now - 600 => "SLOT_EXPIRED_BEYOND_SKEW",
        "exp" => "SLOT_VALID_FUTURE_EXP",
        "nbf" if number > now + 600 => "SLOT_FUTURE_NBF_BEYOND_SKEW",
        "nbf" => "SLOT_PAST_NBF",
        _ => "SLOT_TIME_CLAIM",
    };
    *value = Value::String(format!("{{{{{classification}}}}}"));
}

fn access_signature_role(token: &str) -> &'static str {
    if token_validates_with(
        token,
        Algorithm::RS256,
        &DecodingKey::from_rsa_components(INITIAL_MODULUS, "AQAB")
            .expect("test initial RSA components are valid"),
    ) {
        "initial_rs256"
    } else if token_validates_with(
        token,
        Algorithm::RS256,
        &DecodingKey::from_rsa_components(ROTATED_MODULUS, "AQAB")
            .expect("test rotated RSA components are valid"),
    ) {
        "rotated_rs256"
    } else if token_validates_with(
        token,
        Algorithm::HS256,
        &DecodingKey::from_secret(b"synthetic-access-test-signing-slot"),
    ) {
        "synthetic_hs256"
    } else {
        "unverified"
    }
}

fn token_validates_with(token: &str, algorithm: Algorithm, key: &DecodingKey) -> bool {
    let mut validation = Validation::new(algorithm);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    decode::<Value>(token, key, &validation).is_ok()
}

fn base64url_decode(value: &str) -> TestResult<Vec<u8>> {
    let mut decoded = Vec::with_capacity(value.len() * 3 / 4);
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for byte in value.bytes() {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return Err(io::Error::other("Access assertion used invalid base64url").into()),
        };
        accumulator = (accumulator << 6) | u32::from(digit);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            decoded.push((accumulator >> bits) as u8);
            accumulator &= (1_u32 << bits).saturating_sub(1);
        }
    }
    if bits > 0 && accumulator != 0 {
        return Err(io::Error::other("Access assertion base64url tail was invalid").into());
    }
    Ok(decoded)
}

fn write_server_config(root: &Path, fixture: &JwksFixture) -> TestResult<PathBuf> {
    let root = root.canonicalize()?;
    let secret_directory = root.join("secrets");
    fs::create_dir(&secret_directory)?;
    let subject_key_file = root.join("subject.key");
    fs::write(&subject_key_file, SUBJECT_KEY)?;
    set_restricted_permissions(&subject_key_file)?;
    let ui_assets_directory = root.join("ui-dist");
    build_test_ui(&ui_assets_directory)?;
    let config = json!({
        "schema": "zode.server-config.v1",
        "listen": "127.0.0.1:0",
        "server_authority_id": "access-e2e-server",
        "deployment": "server_only",
        "ui_mode": "assets",
        "ui_assets_directory": "ui-dist",
        "control_database": root.join("control.sqlite"),
        "secret_directory": secret_directory,
        "access": {
            "issuer": fixture.issuer(),
            "audiences": [AUDIENCE],
            "jwks_url": fixture.jwks_url(),
            "subject_key_file": subject_key_file,
            "subject_key_version": 1,
        },
    });
    let path = root.join("server.json");
    fs::write(&path, serde_json::to_vec(&config)?)?;
    Ok(path)
}

fn build_test_ui(ui_assets_directory: &Path) -> TestResult<()> {
    let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| io::Error::other("server manifest has no repository parent"))?;
    let web_root = repository_root.join("web").canonicalize()?;
    let output = Command::new("pnpm")
        .current_dir(&web_root)
        .arg("exec")
        .arg("vp")
        .arg("build")
        .arg("--outDir")
        .arg(ui_assets_directory)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "real web vp build failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
        .into());
    }

    validate_test_ui(ui_assets_directory)
}

fn validate_test_ui(ui_assets_directory: &Path) -> TestResult<()> {
    let index_path = ui_assets_directory.join("index.html");
    let index = fs::read_to_string(&index_path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "real web build did not produce {}: {error}",
                index_path.display()
            ),
        )
    })?;
    if !index.contains("<html") {
        return Err(io::Error::other("real web build index.html is not an HTML document").into());
    }

    let asset = index
        .match_indices("assets/")
        .find_map(|(offset, _)| {
            let candidate = &index[offset..];
            let end = candidate
                .find(|character: char| {
                    matches!(
                        character,
                        '"' | '\'' | ' ' | '\n' | '\r' | ')' | '>' | '?' | '#'
                    )
                })
                .unwrap_or(candidate.len());
            let relative = &candidate[..end];
            let mut components = relative.split('/');
            if components.next() != Some("assets") {
                return None;
            }
            let file_name = components.next()?;
            if components.next().is_some() || !hashed_asset_file_name(file_name) {
                return None;
            }
            Some(PathBuf::from(relative))
        })
        .ok_or_else(|| {
            io::Error::other("real web build index.html has no hashed asset reference")
        })?;
    let asset_path = ui_assets_directory.join(&asset);
    let metadata = fs::symlink_metadata(&asset_path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "real web build asset is missing {}: {error}",
                asset_path.display()
            ),
        )
    })?;
    if !metadata.file_type().is_file() || metadata.len() == 0 {
        return Err(io::Error::other(format!(
            "real web build asset is not a non-empty regular file: {}",
            asset_path.display()
        ))
        .into());
    }
    Ok(())
}

fn hashed_asset_file_name(file_name: &str) -> bool {
    let Some((stem, _extension)) = file_name.rsplit_once('.') else {
        return false;
    };
    let Some((_prefix, hash)) = stem.rsplit_once('-') else {
        return false;
    };
    hash.len() >= 8
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn write_catalog_endpoint_config(root: &Path) -> TestResult<PathBuf> {
    fs::create_dir_all(root)?;
    fs::create_dir(root.join("credentials"))?;
    fs::create_dir(root.join("blobs"))?;
    let controller_secret = root.join("controller.secret");
    fs::write(&controller_secret, CATALOG_CONTROLLER_SECRET)?;
    set_restricted_permissions(&controller_secret)?;
    let config = json!({
        "schema": "zode.config.v1",
        "listen": "127.0.0.1:0",
        "runtime_store": {
            "kind": "sqlite",
            "path": root.join("runtime.sqlite")
        },
        "credential_replica_store": {
            "kind": "files",
            "directory": "credentials"
        },
        "blob_store": {
            "kind": "files",
            "directory": "blobs"
        },
        "controller_auth": [{
            "authority_id": CATALOG_CONTROLLER_AUTHORITY,
            "revision": 1,
            "kind": "bearer_secret_file",
            "secret_file": "controller.secret"
        }],
        "runtime": {
            "tool_foreground_ms": 100,
            "snapshot_every_events": 8,
            "max_rounds_per_activation": 4,
            "model_step_max_attempts": 1,
            "model_retry_base_ms": 1,
            "model_retry_max_ms": 1
        },
        "provider_execution": {
            "adapter_kinds": ["openai_compatible"],
            "allowed_base_url_origins": ["http://127.0.0.1"]
        },
        "callback": {
            "allowed_public_origins": ["http://127.0.0.1"]
        },
        "tools": []
    });
    let path = root.join("endpoint.json");
    fs::write(&path, serde_json::to_vec(&config)?)?;
    Ok(path)
}

fn catalog_endpoint_identity(base_url: &str) -> TestResult<Value> {
    let raw = raw_http_request_with_body(
        base_url,
        "GET",
        "/v1/identity",
        &[
            IncidentHeader {
                name: "Authorization".to_owned(),
                value: format!("Bearer {CATALOG_CONTROLLER_SECRET}"),
            },
            IncidentHeader {
                name: "Zode-Subject".to_owned(),
                value: CATALOG_DIRECT_SUBJECT.to_owned(),
            },
        ],
        &[],
    )?;
    assert_raw_markers_absent(
        &raw.response,
        &[CATALOG_CONTROLLER_SECRET, CATALOG_DIRECT_SUBJECT],
    )?;
    let response = parse_http_response(&raw.response)?;
    if response.status != 200 {
        return Err(io::Error::other(format!(
            "real Endpoint identity barrier expected HTTP 200, got {}",
            response.status
        ))
        .into());
    }
    let identity: Value = serde_json::from_slice(&response.body)?;
    if identity["schema"] != "zode.identity.v1"
        || identity["protocol_version"] != "zode.endpoint.v1"
        || identity["authority_id"] != CATALOG_CONTROLLER_AUTHORITY
        || identity["revision"] != 1
        || identity["endpoint_id"].as_str().is_none_or(str::is_empty)
    {
        return Err(io::Error::other("real Endpoint identity barrier was malformed").into());
    }
    Ok(identity)
}

fn catalog_request(
    base_url: &str,
    method: &str,
    path: &str,
    assertion: &str,
    idempotency_key: Option<&str>,
    body: Option<&[u8]>,
    forbidden: &[&str],
) -> TestResult<HttpResponse> {
    let mut headers = vec![IncidentHeader {
        name: "Cf-Access-Jwt-Assertion".to_owned(),
        value: assertion.to_owned(),
    }];
    if let Some(key) = idempotency_key {
        headers.push(IncidentHeader {
            name: "Idempotency-Key".to_owned(),
            value: key.to_owned(),
        });
    }
    if body.is_some() {
        headers.push(IncidentHeader {
            name: "Content-Type".to_owned(),
            value: "application/json".to_owned(),
        });
    }
    let raw = raw_http_request_with_body(base_url, method, path, &headers, body.unwrap_or(&[]))?;
    assert_raw_markers_absent(&raw.response, forbidden)?;
    parse_http_response(&raw.response)
}

fn assert_raw_markers_absent(bytes: &[u8], markers: &[&str]) -> TestResult<()> {
    for marker in markers {
        if !marker.is_empty()
            && bytes
                .windows(marker.len())
                .any(|window| window == marker.as_bytes())
        {
            return Err(
                io::Error::other("public response disclosed a catalog secret or identity").into(),
            );
        }
    }
    Ok(())
}

fn assert_catalog_safe_unauthorized(response: &HttpResponse) -> TestResult<()> {
    let mut failures = Vec::new();
    check_incident_contract(
        "catalog bootstrap invalid Access assertion",
        ContractKind::SafeUnauthorized,
        response,
        &mut failures,
    );
    if failures.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(failures.join("; ")).into())
    }
}

fn assert_endpoint_list(
    label: &str,
    response: &HttpResponse,
    expected_endpoint_id: Option<&str>,
) -> TestResult<()> {
    if response.status != 200 {
        return Err(io::Error::other(format!(
            "{label} expected HTTP 200, got {}",
            response.status
        ))
        .into());
    }
    let body: Value = serde_json::from_slice(&response.body)?;
    let schema = body["schema"]
        .as_str()
        .ok_or_else(|| io::Error::other(format!("{label} omitted a versioned schema")))?;
    if !schema.starts_with("zode.") || !schema.ends_with(".v1") {
        return Err(io::Error::other(format!("{label} schema was not versioned")).into());
    }
    let items = body["items"]
        .as_array()
        .ok_or_else(|| io::Error::other(format!("{label} omitted items")))?;
    match expected_endpoint_id {
        None if items.is_empty() => Ok(()),
        Some(endpoint_id) if items.len() == 1 => {
            assert_endpoint_record(label, &items[0], endpoint_id)
        }
        None => Err(io::Error::other(format!("{label} was not initially empty")).into()),
        Some(_) => Err(io::Error::other(format!(
            "{label} did not expose exactly one catalog record"
        ))
        .into()),
    }
}

fn assert_endpoint_record(label: &str, record: &Value, endpoint_id: &str) -> TestResult<()> {
    if record["schema"] != "zode.endpoint.v1"
        || record["endpoint_id"] != endpoint_id
        || record["label"] != CATALOG_ENDPOINT_LABEL
        || record["kind"] != "remote"
        || record["status"] != "online"
        || record["disabled"] != false
        || record["controller_authority_id"] != CATALOG_CONTROLLER_AUTHORITY
        || record["controller_credential_revision"] != 1
        || record["capabilities"]["protocol_version"] != "zode.endpoint.v1"
        || !record["capabilities"]["providers"]
            .as_array()
            .is_some_and(|providers| {
                providers
                    .iter()
                    .any(|provider| provider == "openai_compatible")
            })
        || !record["capabilities"]["tools"]
            .as_array()
            .is_some_and(Vec::is_empty)
        || record["last_observed_at_ms"]
            .as_u64()
            .is_none_or(|value| value == 0)
        || record["auth_replica_summary"]["ready"] != 0
        || record["auth_replica_summary"]["pending"] != 0
        || record["auth_replica_summary"]["stale"] != 0
    {
        return Err(io::Error::other(format!(
            "{label} did not match the authoritative Endpoint representation"
        ))
        .into());
    }
    let serialized = serde_json::to_string(record)?;
    for forbidden in ["base_url", "control_auth", CATALOG_CONTROLLER_SECRET] {
        if serialized.contains(forbidden) {
            return Err(io::Error::other(format!(
                "{label} exposed Endpoint connection or credential detail"
            ))
            .into());
        }
    }
    Ok(())
}

fn assert_catalog_capture_safe(
    server: &ServerCapture,
    endpoint: &ServerCapture,
    server_root: &Path,
    endpoint_root: &Path,
    assertions: &[String],
) -> TestResult<()> {
    let mut failures = Vec::new();
    let mut identity_markers = IDENTITY_MARKERS.to_vec();
    identity_markers.push(CATALOG_DIRECT_SUBJECT);
    scan_bytes(
        "catalog Server stdout",
        &server.stdout,
        &identity_markers,
        &mut failures,
    );
    scan_bytes(
        "catalog Server stderr",
        &server.stderr,
        &identity_markers,
        &mut failures,
    );
    scan_bytes(
        "catalog Endpoint stdout",
        &endpoint.stdout,
        &identity_markers,
        &mut failures,
    );
    scan_bytes(
        "catalog Endpoint stderr",
        &endpoint.stderr,
        &identity_markers,
        &mut failures,
    );
    for assertion in assertions {
        for (label, bytes) in [
            ("catalog Server stdout", server.stdout.as_slice()),
            ("catalog Server stderr", server.stderr.as_slice()),
            ("catalog Endpoint stdout", endpoint.stdout.as_slice()),
            ("catalog Endpoint stderr", endpoint.stderr.as_slice()),
        ] {
            scan_dynamic_bytes(label, bytes, assertion, &mut failures);
        }
        scan_tree_dynamic(server_root, assertion, &mut failures)?;
        scan_tree_dynamic(endpoint_root, assertion, &mut failures)?;
    }
    for marker in identity_markers {
        scan_tree_dynamic(server_root, marker, &mut failures)?;
        scan_tree_dynamic(endpoint_root, marker, &mut failures)?;
    }
    for (label, bytes) in [
        ("catalog Server stdout", server.stdout.as_slice()),
        ("catalog Server stderr", server.stderr.as_slice()),
        ("catalog Endpoint stdout", endpoint.stdout.as_slice()),
        ("catalog Endpoint stderr", endpoint.stderr.as_slice()),
    ] {
        scan_dynamic_bytes(label, bytes, CATALOG_CONTROLLER_SECRET, &mut failures);
    }
    for entry in fs::read_dir(server_root)? {
        let path = entry?.path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("control.sqlite"))
            && path.is_file()
        {
            scan_dynamic_bytes(
                "catalog Server control SQLite/WAL",
                &fs::read(path)?,
                CATALOG_CONTROLLER_SECRET,
                &mut failures,
            );
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(failures.join("; ")).into())
    }
}

fn actor_claims(
    issuer: &str,
    sub: &str,
    common_name: Option<&str>,
    email: &str,
    token_type: &str,
    exp: i64,
) -> Value {
    actor_claims_with_audience(issuer, sub, common_name, email, AUDIENCE, token_type, exp)
}

fn actor_claims_with_audience(
    issuer: &str,
    sub: &str,
    common_name: Option<&str>,
    email: &str,
    audience: &str,
    token_type: &str,
    exp: i64,
) -> Value {
    let mut claims = Map::new();
    claims.insert("iss".into(), Value::String(issuer.into()));
    claims.insert("aud".into(), json!([audience]));
    claims.insert("sub".into(), Value::String(sub.into()));
    if let Some(common_name) = common_name {
        claims.insert("common_name".into(), Value::String(common_name.into()));
    }
    claims.insert("email".into(), Value::String(email.into()));
    claims.insert("type".into(), Value::String(token_type.into()));
    claims.insert("exp".into(), json!(exp));
    claims.insert("nbf".into(), json!(unix_seconds() - 60));
    Value::Object(claims)
}

fn actor_claims_with_times(
    issuer: &str,
    sub: &str,
    common_name: Option<&str>,
    email: &str,
    token_type: &str,
    exp: i64,
    nbf: i64,
) -> Value {
    let mut claims =
        actor_claims_with_audience(issuer, sub, common_name, email, AUDIENCE, token_type, exp);
    claims
        .as_object_mut()
        .expect("claims object")
        .insert("nbf".into(), json!(nbf));
    claims
}

fn non_string_subject_claims(issuer: &str, exp: i64) -> Value {
    let mut claims = actor_claims(
        issuer,
        "ignored",
        None,
        "non-string@example.invalid",
        "app",
        exp,
    );
    claims
        .as_object_mut()
        .expect("claims object")
        .insert("sub".into(), json!(42));
    claims
}

fn signed_token(private_key: &str, kid: &str, claims: Value) -> TestResult<String> {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    Ok(encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(private_key.as_bytes())?,
    )?)
}

fn signed_token_without_kid(private_key: &str, claims: Value) -> TestResult<String> {
    let header = Header::new(Algorithm::RS256);
    Ok(encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(private_key.as_bytes())?,
    )?)
}

fn signed_hs256_token(secret: &str, claims: Value) -> TestResult<String> {
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(JWKS_INITIAL_KID.to_owned());
    Ok(encode(
        &header,
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?)
}

fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs() as i64
}

fn raw_http_request_with_incident_headers(
    base_url: &str,
    method: &str,
    path: &str,
    headers: &[IncidentHeader],
) -> TestResult<RawHttpExchange> {
    raw_http_request_with_body(base_url, method, path, headers, &[])
}

fn raw_http_request_with_body(
    base_url: &str,
    method: &str,
    path: &str,
    headers: &[IncidentHeader],
    body: &[u8],
) -> TestResult<RawHttpExchange> {
    let url = Url::parse(base_url)?;
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "server URL has no host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "server URL has no port"))?;
    let mut stream = TcpStream::connect((host, port))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n");
    for header in headers {
        request.push_str(&header.name);
        request.push_str(": ");
        request.push_str(&header.value);
        request.push_str("\r\n");
    }
    if !body.is_empty() {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    let mut request_bytes = request.into_bytes();
    request_bytes.extend_from_slice(body);
    stream.write_all(&request_bytes)?;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes)?;
    Ok(RawHttpExchange {
        request: request_bytes,
        response: bytes,
    })
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn parse_http_response(bytes: &[u8]) -> TestResult<HttpResponse> {
    let header_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP headers incomplete"))?;
    let header_text = std::str::from_utf8(&bytes[..header_end])?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP status missing"))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
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
    let body = if headers.iter().any(|(name, value)| {
        name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked")
    }) {
        decode_chunked(raw_body)?
    } else if let Some(length) = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .map(|(_, value)| value.parse::<usize>())
    {
        let length = length?;
        raw_body.get(..length).unwrap_or(raw_body).to_vec()
    } else {
        raw_body.to_vec()
    };
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

fn sanitize_exchange(
    raw: &RawHttpExchange,
    sequence: u64,
    case: IncidentCase,
    material: &RequestMaterial,
) -> TestResult<IncidentExchange> {
    let request = canonicalize_captured_request(&parse_raw_request(&raw.request)?, case, material)?;
    let response = incident_response(&parse_http_response(&raw.response)?)?;
    if response.status != 404 || !response.body_hex.is_empty() {
        return Err(io::Error::other("initial unmodified Server response was not HTTP 404").into());
    }
    assert_response_secret_free(&raw.response, &material.secret_values)?;
    Ok(IncidentExchange {
        sequence,
        slot: case.slot.to_owned(),
        phase: incident_phase(case).to_owned(),
        concurrent_group: case.concurrent_group.map(str::to_owned),
        request,
        recorded_response: response,
        contract: IncidentContract {
            status: case.contract.status(),
            kind: case.contract.name().to_owned(),
        },
    })
}

fn parse_raw_request(bytes: &[u8]) -> TestResult<RawRequestShape> {
    let header_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "captured request incomplete"))?;
    let text = std::str::from_utf8(&bytes[..header_end])?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "captured request line missing")
    })?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "captured request method missing",
        )
    })?;
    let path = parts.next().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "captured request path missing")
    })?;
    let mut headers = Vec::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "captured request header malformed",
            )
        })?;
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        headers.push(IncidentHeader {
            name,
            value: value.to_owned(),
        });
    }
    Ok(RawRequestShape {
        method: method.to_owned(),
        path: path.to_owned(),
        headers,
        body: bytes[header_end + 4..].to_vec(),
    })
}

fn canonicalize_captured_request(
    request: &RawRequestShape,
    case: IncidentCase,
    material: &RequestMaterial,
) -> TestResult<IncidentRequest> {
    if request.method != case.method || request.path != case.path {
        return Err(io::Error::other("captured public request did not match its case").into());
    }
    let semantic_headers = request
        .headers
        .iter()
        .filter(|header| {
            !matches!(
                header.name.as_str(),
                "host" | "connection" | "content-length"
            )
        })
        .map(|header| {
            let secret = material
                .secret_values
                .iter()
                .find(|secret| secret.value == header.value)
                .ok_or_else(|| {
                    io::Error::other(
                        "captured request contained an unrecorded semantic header value",
                    )
                })?;
            Ok(IncidentHeader {
                name: header.name.clone(),
                value: format!("{{{{{}}}}}", secret.slot),
            })
        })
        .collect::<TestResult<Vec<_>>>()?;
    if semantic_headers != material.semantic_headers {
        return Err(
            io::Error::other("captured request did not match its synthetic secret slots").into(),
        );
    }
    make_incident_request(
        request.method.clone(),
        request.path.clone(),
        semantic_headers,
        request.body.clone(),
    )
}

fn make_incident_request(
    method: String,
    path: String,
    semantic_headers: Vec<IncidentHeader>,
    body: Vec<u8>,
) -> TestResult<IncidentRequest> {
    let canonical_json = if body.is_empty() {
        None
    } else {
        Some(serde_json::from_slice(&body)?)
    };
    let mut request = IncidentRequest {
        method,
        path,
        semantic_headers_sha256: incident_headers_digest(&semantic_headers)?,
        semantic_headers,
        raw_body_hex: hex_encode(&body),
        canonical_json,
        body_sha256: sha256_hex(&body),
        fingerprint: String::new(),
    };
    request.fingerprint = incident_request_fingerprint(&request)?;
    Ok(request)
}

fn incident_response(response: &HttpResponse) -> TestResult<IncidentResponse> {
    let semantic_headers = response
        .headers
        .iter()
        .filter(|(name, _)| matches!(name.as_str(), "content-type" | "cache-control" | "vary"))
        .map(|(name, value)| IncidentHeader {
            name: name.clone(),
            value: value.clone(),
        })
        .collect::<Vec<_>>();
    let mut recorded = IncidentResponse {
        status: response.status,
        semantic_headers_sha256: incident_headers_digest(&semantic_headers)?,
        semantic_headers,
        body_hex: hex_encode(&response.body),
        body_sha256: sha256_hex(&response.body),
        outcome: "complete".to_owned(),
        fingerprint: String::new(),
    };
    recorded.fingerprint = incident_response_fingerprint(&recorded)?;
    Ok(recorded)
}

fn incident_phase(case: IncidentCase) -> &'static str {
    match case.concurrent_group {
        Some("unknown-kid-singleflight") => "jwks_rotation_singleflight",
        Some("unknown-kid-fail-closed") => "jwks_refresh_fail_closed",
        Some(_) => "invalid_concurrent_group",
        None => match case.contract {
            ContractKind::System => "management_admission",
            ContractKind::SafeUnauthorized => "ingress_rejection",
            ContractKind::NotFound => "absence_of_local_identity_routes",
        },
    }
}

fn expanded_incident_cases() -> Vec<IncidentCase> {
    let mut expanded = Vec::new();
    for case in incident_cases() {
        match case.concurrent_group {
            None => expanded.push(case),
            Some("unknown-kid-singleflight") => expanded.extend([case; 4]),
            Some("unknown-kid-fail-closed") => expanded.push(case),
            Some(_) => {}
        }
    }
    expanded
}

fn validate_cassette(cassette: &IncidentCassette) -> TestResult<()> {
    if cassette.schema != INCIDENT_CASSETTE_SCHEMA
        || cassette.recording_id != INCIDENT_RECORDING_ID
        || cassette.source_recording_id != INCIDENT_SOURCE_RECORDING_ID
        || cassette.purpose
            != "Replay the retained first public HTTP 404 with exact synthetic-slot semantics and the reviewed Access admission contract"
        || cassette.owner != INCIDENT_OWNER
        || cassette.boundary != INCIDENT_BOUNDARY
        || cassette.first_observed_outcome.sequence != 0
        || cassette.first_observed_outcome.status != 404
        || cassette.first_observed_outcome.safe_error != "empty_router_http_404"
        || cassette.first_observed_outcome.observed_jwks_requests != 0
        || cassette.envelope_sha256 != incident_envelope_digest(cassette)?
    {
        return Err(io::Error::other("incident cassette metadata is invalid").into());
    }
    let cases = expanded_incident_cases();
    if cassette.exchanges.len() != cases.len() {
        return Err(io::Error::other("incident cassette exchange count is invalid").into());
    }
    let mut used_slots = BTreeSet::new();
    for (sequence, (exchange, case)) in cassette.exchanges.iter().zip(cases).enumerate() {
        if exchange.sequence != sequence as u64
            || exchange.slot != case.slot
            || exchange.phase != incident_phase(case)
            || exchange.concurrent_group.as_deref() != case.concurrent_group
            || exchange.request.method != case.method
            || exchange.request.path != case.path
            || exchange.contract.status != case.contract.status()
            || exchange.contract.kind != case.contract.name()
            || !exchange.request.raw_body_hex.is_empty()
            || exchange.request.canonical_json.is_some()
            || exchange.request.body_sha256 != sha256_hex(&[])
            || exchange.request.semantic_headers_sha256
                != incident_headers_digest(&exchange.request.semantic_headers)?
            || exchange.request.fingerprint != incident_request_fingerprint(&exchange.request)?
            || exchange.recorded_response.status != 404
            || !exchange.recorded_response.body_hex.is_empty()
            || exchange.recorded_response.body_sha256 != sha256_hex(&[])
            || exchange.recorded_response.semantic_headers_sha256
                != incident_headers_digest(&exchange.recorded_response.semantic_headers)?
            || exchange.recorded_response.outcome != "complete"
            || exchange.recorded_response.fingerprint
                != incident_response_fingerprint(&exchange.recorded_response)?
        {
            return Err(io::Error::other("incident cassette case was altered").into());
        }
        validate_recorded_headers(case, &exchange.request.semantic_headers, &mut used_slots)?;
        for header in &exchange.recorded_response.semantic_headers {
            if !matches!(
                header.name.as_str(),
                "content-type" | "cache-control" | "vary"
            ) || contains_forbidden_header_name(&header.name)
            {
                return Err(
                    io::Error::other("incident response headers are not secret-safe").into(),
                );
            }
        }
    }
    let recorded_slots = cassette
        .secret_slots
        .iter()
        .map(|slot| slot.name.clone())
        .collect::<BTreeSet<_>>();
    if recorded_slots.len() != cassette.secret_slots.len()
        || cassette.secret_slots.iter().any(|slot| {
            !slot.name.starts_with("SLOT_")
                || !matches!(
                    slot.kind.as_str(),
                    "access_assertion" | "custom_identity_header"
                )
                || slot.semantic_sha256.len() != 64
                || !slot
                    .semantic_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        || recorded_slots != used_slots
    {
        return Err(io::Error::other("incident cassette secret slots are invalid").into());
    }
    let first = cassette
        .exchanges
        .first()
        .ok_or_else(|| io::Error::other("incident cassette has no first exchange"))?;
    if cassette.first_observed_outcome.response_fingerprint != first.recorded_response.fingerprint {
        return Err(io::Error::other("incident first-failure fingerprint was altered").into());
    }
    Ok(())
}

fn validate_recorded_headers(
    case: IncidentCase,
    headers: &[IncidentHeader],
    used_slots: &mut BTreeSet<String>,
) -> TestResult<()> {
    let expected_names: &[&str] = match case.slot {
        "missing-assertion" => &[],
        "duplicate-assertion" => &["cf-access-jwt-assertion", "cf-access-jwt-assertion"],
        "custom-identity-headers" => &[
            "cf-authorization",
            "cf-access-authenticated-user-email",
            "x-zode-subject",
        ],
        _ => &["cf-access-jwt-assertion"],
    };
    if headers.len() != expected_names.len()
        || headers
            .iter()
            .zip(expected_names)
            .any(|(header, expected)| header.name != *expected)
    {
        return Err(io::Error::other("incident request header shape was altered").into());
    }
    for header in headers {
        if contains_forbidden_header_name(&header.name)
            && header.name != "cf-access-jwt-assertion"
            && case.slot != "custom-identity-headers"
        {
            return Err(
                io::Error::other("incident request header is outside its reviewed case").into(),
            );
        }
        let slot = header
            .value
            .strip_prefix("{{")
            .and_then(|value| value.strip_suffix("}}"))
            .filter(|value| value.starts_with("SLOT_"))
            .ok_or_else(|| io::Error::other("incident request retained a raw sensitive header"))?;
        used_slots.insert(slot.to_owned());
    }
    Ok(())
}

fn contains_forbidden_header_name(name: &str) -> bool {
    matches!(
        name,
        "authorization" | "cookie" | "set-cookie" | "proxy-authorization"
    )
}

fn incident_request_fingerprint(request: &IncidentRequest) -> TestResult<String> {
    let mut canonical = request.clone();
    canonical.fingerprint.clear();
    Ok(sha256_hex(&serde_json::to_vec(&canonical)?))
}

fn incident_headers_digest(headers: &[IncidentHeader]) -> TestResult<String> {
    Ok(sha256_hex(&serde_json::to_vec(headers)?))
}

fn incident_response_fingerprint(response: &IncidentResponse) -> TestResult<String> {
    let mut canonical = response.clone();
    canonical.fingerprint.clear();
    Ok(sha256_hex(&serde_json::to_vec(&canonical)?))
}

fn incident_envelope_digest(cassette: &IncidentCassette) -> TestResult<String> {
    let mut canonical = cassette.clone();
    canonical.envelope_sha256.clear();
    Ok(sha256_hex(&serde_json::to_vec(&canonical)?))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn sha256_hex(bytes: &[u8]) -> String {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const ROUND: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let bit_length = (bytes.len() as u64).wrapping_mul(8);
    let mut padded = bytes.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());

    let mut state = INITIAL;
    for chunk in padded.chunks_exact(64) {
        let mut words = [0_u32; 64];
        for (index, word) in words.iter_mut().take(16).enumerate() {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                chunk[offset],
                chunk[offset + 1],
                chunk[offset + 2],
                chunk[offset + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temporary1 = h
                .wrapping_add(sum1)
                .wrapping_add(choose)
                .wrapping_add(ROUND[index])
                .wrapping_add(words[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temporary2 = sum0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temporary1);
            d = c;
            c = b;
            b = a;
            a = temporary1.wrapping_add(temporary2);
        }
        for (value, addition) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *value = value.wrapping_add(addition);
        }
    }

    state
        .iter()
        .map(|word| format!("{word:08x}"))
        .collect::<String>()
}

fn read_incident_cassette() -> TestResult<IncidentCassette> {
    let path = incident_cassette_path();
    assert_immutable_fixture(&path)?;
    let bytes = fs::read(path)?;
    scan_fixture_bytes(&bytes, &[])?;
    let cassette: IncidentCassette = serde_json::from_slice(&bytes)?;
    validate_cassette(&cassette)?;
    validate_source_cassette(&cassette)?;
    Ok(cassette)
}

fn validate_source_cassette(cassette: &IncidentCassette) -> TestResult<()> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(INCIDENT_SOURCE_CASSETTE_PATH);
    assert_immutable_fixture(&path)?;
    let bytes = fs::read(path)?;
    scan_fixture_bytes(&bytes, &[])?;
    let source: Value = serde_json::from_slice(&bytes)?;
    if source.get("schema").and_then(Value::as_str) != Some(INCIDENT_CASSETTE_SCHEMA)
        || source.get("recording_id").and_then(Value::as_str)
            != Some(cassette.source_recording_id.as_str())
        || source
            .pointer("/first_observed_outcome/status")
            .and_then(Value::as_u64)
            != Some(404)
        || source
            .pointer("/first_observed_outcome/response_fingerprint")
            .and_then(Value::as_str)
            != Some(
                cassette
                    .first_observed_outcome
                    .response_fingerprint
                    .as_str(),
            )
    {
        return Err(io::Error::other(
            "final Access cassette was detached from its immutable first-failure source",
        )
        .into());
    }
    Ok(())
}

fn assert_immutable_fixture(path: &Path) -> TestResult<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::other("incident cassette is not a regular file").into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Git records only the executable bit, not restrictive read-only
        // modes. Normalize a tracked checkout before the immutable check;
        // promotion itself still uses create-new + 0444 and this path is
        // rejected above when it is a symlink.
        if metadata.permissions().mode() & 0o222 != 0 {
            set_readonly_permissions(path)?;
        }
        if fs::metadata(path)?.permissions().mode() & 0o222 != 0 {
            return Err(io::Error::other("incident cassette was writable").into());
        }
    }
    Ok(())
}

fn write_new_json<T: Serialize>(path: &Path, value: &T) -> TestResult<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    set_restricted_permissions(path)?;
    Ok(())
}

fn promote_immutable_cassette(restricted: &Path, destination: &Path) -> TestResult<()> {
    let bytes = fs::read(restricted)?;
    scan_fixture_bytes(&bytes, &[])?;
    if destination.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "incident cassette promotion refuses to overwrite an existing artifact",
        )
        .into());
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o444);
    }
    let mut file = options.open(destination)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    set_readonly_permissions(destination)?;
    if let Some(parent) = destination.parent() {
        if let Ok(directory) = File::open(parent) {
            let _ = directory.sync_all();
        }
    }
    Ok(())
}

fn set_restricted_permissions(path: &Path) -> TestResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

fn set_readonly_permissions(path: &Path) -> TestResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o444);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

fn scan_fixture_bytes(bytes: &[u8], dynamic_markers: &[String]) -> TestResult<()> {
    let static_markers = [
        "-----BEGIN",
        "eyJ",
        std::str::from_utf8(SUBJECT_KEY).unwrap_or(""),
        "MIIEpAIBAAKCAQEA",
        "MIIEpQIBAAKCAQEA",
        HUMAN_SUB,
        SERVICE_NAME,
        HUMAN_EMAIL,
        "forged-human",
        "rotated-human",
        "expired-human",
        "future-nbf-human",
    ];
    if static_markers.iter().any(|marker| {
        bytes
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
    }) || IDENTITY_MARKERS.iter().any(|marker| {
        bytes
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
    }) || dynamic_markers.iter().any(|marker| {
        bytes
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
    }) {
        return Err(io::Error::other("incident artifact contains forbidden material").into());
    }
    Ok(())
}

fn decode_chunked(mut bytes: &[u8]) -> TestResult<Vec<u8>> {
    let mut decoded = Vec::new();
    loop {
        let line_end = bytes
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunk size missing"))?;
        let size = usize::from_str_radix(
            std::str::from_utf8(&bytes[..line_end])?
                .split(';')
                .next()
                .unwrap_or(""),
            16,
        )?;
        bytes = &bytes[line_end + 2..];
        if size == 0 {
            return Ok(decoded);
        }
        if bytes.len() < size + 2 || &bytes[size..size + 2] != b"\r\n" {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "chunk truncated").into());
        }
        decoded.extend_from_slice(&bytes[..size]);
        bytes = &bytes[size + 2..];
    }
}

fn scan_response(label: &str, response: &HttpResponse, failures: &mut Vec<String>) {
    let forbidden = IDENTITY_MARKERS;
    for (name, value) in &response.headers {
        if forbidden.iter().any(|needle| value.contains(needle)) {
            failures.push(format!(
                "{label}: response header disclosed identity material"
            ));
        }
        if name == "set-cookie" {
            failures.push(format!("{label}: response set an application cookie"));
        }
    }
    if forbidden.iter().any(|needle| {
        response
            .body
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
    }) {
        failures.push(format!(
            "{label}: response body disclosed identity material"
        ));
    }
}

fn scan_bytes(label: &str, bytes: &[u8], forbidden: &[&str], failures: &mut Vec<String>) {
    for needle in forbidden {
        if bytes
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
        {
            failures.push(format!(
                "{label} disclosed persisted Access identity material"
            ));
            break;
        }
    }
}

fn scan_dynamic_bytes(label: &str, bytes: &[u8], marker: &str, failures: &mut Vec<String>) {
    if bytes
        .windows(marker.len())
        .any(|window| window == marker.as_bytes())
    {
        failures.push(format!(
            "{label} disclosed captured Access assertion material"
        ));
    }
}

fn scan_tree(root: &Path, forbidden: &[&str], failures: &mut Vec<String>) -> io::Result<()> {
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            scan_tree(&path, forbidden, failures)?;
        } else if path.is_file() {
            let mut file = File::open(&path)?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            scan_bytes("Server temporary store", &bytes, forbidden, failures);
        }
    }
    Ok(())
}

fn scan_tree_dynamic(root: &Path, marker: &str, failures: &mut Vec<String>) -> io::Result<()> {
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            scan_tree_dynamic(&path, marker, failures)?;
        } else if path.is_file() {
            let mut file = File::open(&path)?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            scan_dynamic_bytes("Server temporary store", &bytes, marker, failures);
        }
    }
    Ok(())
}

fn scan_static_secret_material(
    root: &Path,
    capture: &ServerCapture,
    failures: &mut Vec<String>,
) -> io::Result<()> {
    let markers = [
        SUBJECT_KEY.as_slice(),
        b"MIIEpAIBAAKCAQEA".as_slice(),
        b"MIIEpQIBAAKCAQEA".as_slice(),
    ];
    for (label, bytes) in [
        ("Server stdout", capture.stdout.as_slice()),
        ("Server stderr", capture.stderr.as_slice()),
    ] {
        if markers
            .iter()
            .any(|marker| bytes.windows(marker.len()).any(|window| window == *marker))
        {
            failures.push(format!("{label} disclosed Access key material"));
        }
    }
    scan_tree_static_secret(root, &root.join("subject.key"), &markers, failures)
}

fn scan_tree_static_secret(
    root: &Path,
    allowed_subject_key: &Path,
    markers: &[&[u8]],
    failures: &mut Vec<String>,
) -> io::Result<()> {
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path == allowed_subject_key {
            continue;
        }
        if path.is_dir() {
            scan_tree_static_secret(&path, allowed_subject_key, markers, failures)?;
        } else if path.is_file() {
            let bytes = fs::read(&path)?;
            if markers
                .iter()
                .any(|marker| bytes.windows(marker.len()).any(|window| window == *marker))
            {
                failures.push("Server store contained Access key material".to_owned());
            }
        }
    }
    Ok(())
}

struct JwksFixture {
    address: SocketAddr,
    rotated: Arc<AtomicBool>,
    failure: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
    response_gate: Arc<(Mutex<bool>, Condvar)>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl JwksFixture {
    fn start() -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let rotated = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicUsize::new(0));
        let response_gate = Arc::new((Mutex::new(false), Condvar::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_rotated = Arc::clone(&rotated);
        let thread_failure = Arc::clone(&failure);
        let thread_requests = Arc::clone(&requests);
        let thread_response_gate = Arc::clone(&response_gate);
        let thread_stop = Arc::clone(&stop);
        let join = thread::spawn(move || {
            let mut workers = Vec::new();
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let rotated = Arc::clone(&thread_rotated);
                        let failure = Arc::clone(&thread_failure);
                        let requests = Arc::clone(&thread_requests);
                        let response_gate = Arc::clone(&thread_response_gate);
                        workers.push(thread::spawn(move || {
                            let _ = serve_jwks_connection(
                                stream,
                                &rotated,
                                &failure,
                                &requests,
                                &response_gate,
                            );
                        }));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
            let (held, released) = &*thread_response_gate;
            if let Ok(mut held) = held.lock() {
                *held = false;
                released.notify_all();
            }
            for worker in workers {
                let _ = worker.join();
            }
        });
        Ok(Self {
            address,
            rotated,
            failure,
            requests,
            response_gate,
            stop,
            join: Some(join),
        })
    }

    fn issuer(&self) -> String {
        format!("http://{}{}", self.address, ISSUER_PATH)
    }

    fn jwks_url(&self) -> String {
        format!("http://{}/jwks", self.address)
    }

    fn rotate(&self) {
        self.rotated.store(true, Ordering::Release);
    }

    fn set_failure(&self, failure: bool) {
        self.failure.store(failure, Ordering::Release);
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::Acquire)
    }

    fn hold_responses(&self) -> TestResult<()> {
        let (held, _) = &*self.response_gate;
        let mut held = held
            .lock()
            .map_err(|_| io::Error::other("JWKS response gate lock poisoned"))?;
        if *held {
            return Err(io::Error::other("JWKS response gate was already held").into());
        }
        *held = true;
        Ok(())
    }

    fn release_responses(&self) -> TestResult<()> {
        let (held, released) = &*self.response_gate;
        let mut held = held
            .lock()
            .map_err(|_| io::Error::other("JWKS response gate lock poisoned"))?;
        if !*held {
            return Err(io::Error::other("JWKS response gate was not held").into());
        }
        *held = false;
        released.notify_all();
        Ok(())
    }

    fn wait_for_requests(&self, minimum: usize, timeout: Duration) -> TestResult<bool> {
        let deadline = Instant::now() + timeout;
        let (held, arrived) = &*self.response_gate;
        let mut guard = held
            .lock()
            .map_err(|_| io::Error::other("JWKS response gate lock poisoned"))?;
        while self.request_count() < minimum {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            let (next, result) = arrived
                .wait_timeout(guard, remaining)
                .map_err(|_| io::Error::other("JWKS response gate lock poisoned"))?;
            guard = next;
            if result.timed_out() && self.request_count() < minimum {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl Drop for JwksFixture {
    fn drop(&mut self) {
        if let Ok(mut held) = self.response_gate.0.lock() {
            *held = false;
            self.response_gate.1.notify_all();
        }
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn serve_jwks_connection(
    mut stream: TcpStream,
    rotated: &AtomicBool,
    failure: &AtomicBool,
    requests: &AtomicUsize,
    response_gate: &(Mutex<bool>, Condvar),
) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut request = Vec::new();
    let mut chunk = [0u8; 2048];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") && request.len() < 64 * 1024 {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
    }
    let request_text = String::from_utf8_lossy(&request);
    let path = request_text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("");
    let (status, body) = if path == "/jwks" {
        requests.fetch_add(1, Ordering::AcqRel);
        response_gate.1.notify_all();
        let mut held = response_gate
            .0
            .lock()
            .map_err(|_| io::Error::other("JWKS response gate lock poisoned"))?;
        while *held {
            held = response_gate
                .1
                .wait(held)
                .map_err(|_| io::Error::other("JWKS response gate lock poisoned"))?;
        }
        drop(held);
        if failure.load(Ordering::Acquire) {
            ("503 Service Unavailable", String::new())
        } else {
            ("200 OK", jwks_document(rotated.load(Ordering::Acquire)))
        }
    } else {
        ("404 Not Found", String::new())
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())
}

fn jwks_document(rotated: bool) -> String {
    let (kid, modulus) = if rotated {
        (JWKS_ROTATED_KID, ROTATED_MODULUS)
    } else {
        (JWKS_INITIAL_KID, INITIAL_MODULUS)
    };
    json!({
        "keys": [{
            "kty": "RSA",
            "kid": kid,
            "use": "sig",
            "alg": "RS256",
            "n": modulus,
            "e": "AQAB"
        }]
    })
    .to_string()
}

struct ServerProcess {
    child: Option<Child>,
    base_url: String,
    stdout: Arc<Mutex<Vec<u8>>>,
    stderr: Arc<Mutex<Vec<u8>>>,
    readers: Vec<JoinHandle<()>>,
}

struct ServerCapture {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl ServerProcess {
    fn start(config_path: &Path) -> TestResult<Self> {
        let binary = env::var("CARGO_BIN_EXE_zode-server")
            .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "zode-server binary missing"))?;
        let config_path = config_path.canonicalize()?;
        let process_cwd = server_process_cwd(&config_path)?;
        let mut command = Command::new(binary);
        command
            .current_dir(process_cwd)
            .arg("--config")
            .arg(&config_path);
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
                let _ = reap_child_bounded(&mut child);
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
            base_url,
            stdout,
            stderr,
            readers: vec![stdout_thread, stderr_thread],
        })
    }

    fn stop(&mut self) -> TestResult<ServerCapture> {
        if let Some(mut child) = self.child.take() {
            reap_child_bounded(&mut child)?;
        }
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
        Ok(ServerCapture {
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
        })
    }
}

fn server_process_cwd(config_path: &Path) -> TestResult<PathBuf> {
    let config_directory = config_path
        .parent()
        .ok_or_else(|| io::Error::other("absolute Server config has no parent directory"))?;
    let process_cwd = config_directory.join("server-cwd");
    fs::create_dir_all(&process_cwd)?;
    if process_cwd == config_directory || process_cwd == config_directory.join("ui-dist") {
        return Err(
            io::Error::other("Server process cwd is not isolated from its config/UI").into(),
        );
    }
    Ok(process_cwd)
}

fn endpoint_binary() -> TestResult<PathBuf> {
    let path = env::var_os("ZODE_ENDPOINT_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")))
                .join("target/debug/zode")
        });
    if !path.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "real zode Endpoint binary is missing; build it or set ZODE_ENDPOINT_BIN",
        )
        .into());
    }
    Ok(path)
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = reap_child_bounded(&mut child);
        }
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }
}

fn reap_child_bounded(child: &mut Child) -> TestResult<()> {
    if child.try_wait()?.is_none() {
        let _ = child.kill();
    }
    let deadline = Instant::now() + CHILD_STOP_TIMEOUT;
    loop {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "zode-server child did not stop before the E2E deadline",
            )
            .into());
        }
        thread::sleep(POLL_INTERVAL);
    }
}
