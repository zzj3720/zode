# UI release-pipeline E2E

This directory is an independent black-box harness. It never imports `zode`,
starts no mock router, and does not implement a release manager. The release
driver supplied to it must be the real product release entry that starts the
built Server with its built-in Endpoint.

The executable entry is `run_release_e2e.sh`:

```sh
ZODE_RELEASE_BASELINE_REVISION=<old-commit> \
ZODE_RELEASE_CANDIDATE_REVISION=<candidate-commit> \
ZODE_RELEASE_FAILED_REVISION=<known-health-failing-commit> \
ZODE_RELEASE_DRIVER_RELATIVE_PATH=path/to/the/real-release-entry \
ZODE_RELEASE_UI_URL=http://127.0.0.1:<management-port>/ \
./tests/release_e2e/run_release_e2e.sh --promote-incident
```

## 首次本机测试安装

完整三 revision 发布 E2E 需要 baseline/candidate/failed 三个冻结提交；在
Management all-in-one 纵切尚未 ready 时，不应把 `78/BLOCKED` 当成行为红。
要先交付一个可消费的单 revision 安装，可使用固定 channel 入口：

```sh
node release/channel.cjs build --revision <commit> --output-root <artifact-root>
node release/channel.cjs install --artifact <artifact> --release-root <channel-root>
node release/channel.cjs start --artifact <artifact> --release-root <channel-root>
node release/channel.cjs stop --release-root <channel-root>
node release/channel.cjs update --artifact <candidate> --release-root <channel-root>
```

给本机用户的可留存入口是：

```sh
node release/local-channel.cjs install --artifact <artifact>
node release/local-channel.cjs start
# 打开 start 输出的 URL；停止时：
node release/local-channel.cjs stop
```

该入口默认使用 `~/.zode/test-channel`，也可传 `--channel-root` 固定到
其他本机目录。它保留同一 artifact、持久 Endpoint/Server 状态和本地
Access-protected edge，因此重启后 URL 不变，普通浏览器仍走
Access → Server → built-in Endpoint；edge 不提供未认证 fallback，也不带
recorder/replay/test 参数进入产品进程。配置外部 provider 时只需额外设置不含
凭据的 `ZODE_RELEASE_PROVIDER_ORIGINS`，API key 仍通过 UI profile 输入。

构建只读取 `git archive`，并在同一 revision 内锁定 Endpoint、Server、Vite+
UI、协议输入和 release driver 的 manifest/digest。`install` 不切换运行中
版本；`update` 的 candidate readiness 失败会保留 `current`/`previous` 并返回
非零。启动/停止使用真实产品进程和既有认证边界；它们不新增 release API，
也不接受 cassette、replay 或测试 locator 参数。Management all-in-one ready
后，使用同一个 `channel-root` 启动安装版，再通过真实浏览器执行 UI → Server
→ built-in Endpoint smoke；无需等待完整三 revision rollback 矩阵。

安装入口的真实进程 smoke 可在已有 artifact 上运行：

```sh
ZODE_RELEASE_CHANNEL_ARTIFACT=<artifact> \
  node tests/release_e2e/local_channel_install_e2e.cjs
```

该 smoke 只证明 immutable install 的副作用边界（`releases/` 新增一个版本，
`current`/`previous` 仍不存在），不把尚未具备 all-in-one 的启动失败伪装成
浏览器行为红。

Management all-in-one 进入 main 后，安装版浏览器 smoke 使用同一个 channel
入口启动 artifact，并通过 test-owned Access/JWKS edge 和本地 fake provider
完成真实 UI→Server→built-in Endpoint 操作：

```sh
ZODE_RELEASE_CHANNEL_ARTIFACT=<artifact> \
  node tests/release_e2e/installed_channel_browser_smoke_e2e.cjs
```

该 E2E 不导入产品代码、不启动源码二进制，也不把 Access assertion 或
provider secret 写入 artifact、日志或测试输出；失败首遇只进入 ignored
quarantine。

安装版真实 provider 正向路径由 Rust harness 包住同一浏览器入口，并把
`OPENCODE_GO_API_KEY` 只在测试进程内交给 test-owned recorder。recorder 通过
`https://opencode.ai` 的既有 provider 边界转发，安装版 Server/Endpoint 子进程
不会继承该变量；录制完成后会 flush、扫描并在 ignored quarantine 原子写入
`recording.json`，输出不包含凭据。该入口需要本机已批准的安全 provider 引用，
不会把密钥写入仓库或 cassette：

```sh
OPENCODE_GO_API_KEY=<local-secure-provider-key> \
ZODE_RUN_INSTALLED_CHANNEL_LIVE_BROWSER_E2E=1 \
ZODE_RELEASE_CHANNEL_ARTIFACT=<artifact> \
vp exec cargo test --test installed_channel_live_browser_e2e \
  e2e_installed_channel_live_browser_provider_roundtrip -- --exact --nocapture
```

该正向 E2E 在安装版浏览器中配置 run-owned `zode-installed-live-test` /
`deepseek-v4-flash` provider
及共享 API-key profile，创建 Endpoint session，发送精确 marker 提示词，断言
stream marker（允许模型在 marker 后追加一个终止标点）、Server/Endpoint 管理请求、provider 200/SSE `[DONE]`，再 reload
确认最终回复仍由 durable session 恢复。固定持久根模式还会真实 stop→start，重开同一
session URL，再发送一次普通消息并 reload；两次真实 provider 请求都必须经过
recorder。录制完成前，测试入口只收敛本次 run-owned descriptor，并通过已有的
session model-selection route 迁移该 session 的 concrete execution，避免退出的
recorder 地址残留在用户通道；固定根上若同一身份不是带 ownership marker 的测试
descriptor，测试会在任何写入前失败。当前 Server 没有 profile-delete 公共路由，既有
profile 事实不会被测试入口伪造删除。失败时先保留首遇 browser/quarantine 证据并完成
recorder flush。另有
`installed_channel_live_provider_contract_e2e.cjs` 作为本地 loopback provider
边界的红绿 contract anchor，不替代真实 provider gate。

真实 provider smoke 结束后，Rust live E2E 会在同一根重新启动安装版通道并调用
`installed_channel_persistent_state_e2e.cjs`；它用安装版 Chromium 和公开
Providers/Sessions API 检查 run-owned descriptor、session concrete execution
以及 durable assistant final。任何 test-owned loopback descriptor、session 仍指向
recorder，或没有 durable assistant final 的 `Working` session 都会形成真实持久
状态红，并把首遇安全写入 ignored quarantine；只看到 UI/health 200 不算通过。

持久入口的失败清理与边界也由真实进程 E2E 固定：
`local_channel_open_failure_e2e.cjs` 验证 fresh `open` 健康失败不会留下
edge；`local_channel_edge_admission_e2e.cjs` 验证篡改的非 loopback 状态被
拒绝；`local_channel_stop_identity_e2e.cjs` 验证 stop 不信任 PATH 伪造的
`ps` 身份，也不会杀死无关进程组；`local_channel_update_failure_e2e.cjs`
验证 fresh update 的无效候选不会留下 edge/runtime；
`local_channel_revision_update_e2e.cjs` 使用两个真实 immutable artifact，验证
旧 current 经 candidate readiness 后原子推进到新 revision，并且更新后仍只保留
一个健康的 current 实例；它要求 `ZODE_RELEASE_CHANNEL_BASE_ARTIFACT` 与
`ZODE_RELEASE_CHANNEL_ARTIFACT`。
`local_channel_node_runtime_e2e.cjs` 验证由一套 Node 启动后，另一套受信
Node 仍能按 runtime 中的真实 executable path 检查并停止同一 edge。

The test channel supplies the existing authentication inputs through
`ZODE_RELEASE_ACCESS_ASSERTION` (or `_ACCESS_JWT_ASSERTION`) and
`ZODE_RELEASE_ENDPOINT_CONTROLLER_BEARER` (or `_CONTROLLER_BEARER`). Optional
`ZODE_RELEASE_SERVER_LISTEN` and `ZODE_RELEASE_ENDPOINT_LISTEN` pin the stable
loopback listeners; otherwise the driver allocates isolated loopback ports.
Issuer/JWKS/audience configuration is passed by the corresponding
`ZODE_RELEASE_ACCESS_ISSUER`, `_ACCESS_JWKS_URL`, and `_ACCESS_AUDIENCE`
variable names. Values are never written to manifests, locators, stop reports,
logs, or health JSON.

All three revisions must resolve to immutable commits. The harness archives
each revision into a fresh temporary checkout, builds `web`, `server`, and the
Endpoint there, and writes an immutable `zode.release-artifact.v1` manifest
whose UI/Server/Endpoint component hashes, checkout-selected driver hash, and
`revision` are checked before the immutable driver receives the artifact. A
dirty working tree is not copied into a candidate.

`ZODE_RELEASE_DRIVER_RELATIVE_PATH` selects the real driver from each fresh
immutable checkout. The harness packages the selected executable as
`release-driver`, binds its SHA-256 in the manifest, and invokes that immutable
copy without a shell using this protocol:

```text
<driver> bootstrap --release-root <dir> --artifact <dir> --json
<driver> stage    --release-root <dir> --artifact <dir> --json
<driver> promote  --release-root <dir> --json
<driver> health   --release-root <dir> --json
<driver> rollback --release-root <dir> --json
<driver> teardown --release-root <dir> --json
```

`bootstrap` must install the baseline without a promotion. `stage`
must run the real install/readiness gate and leave `current` untouched until
the driver `promote` action. A failed readiness gate must exit non-zero and
leave `current` and `previous` byte-for-byte unchanged. The driver owns
starting the real Server and built-in Endpoint; it must not use a mock HTTP
handler. The release root is test-owned and must expose `current` and
`previous`, each resolving to a directory containing the checked manifest.
The active `current` process keeps the all-in-one Endpoint runtime store,
Server control store, catalog identity, controller authority, subject key, and
secret directory in one run-owned persistent state directory; each promoted or
rolled-back revision points at those same stores rather than resetting them.
An independently staged `candidate` receives isolated stores and authority so
its SQLite ownership cannot conflict with `current`; promotion adopts the
candidate artifact onto the persistent current stores.

`teardown` must stop and reap every Server/Endpoint child started for the run;
the harness invokes it on success and failure. The harness independently checks
live PIDs, executable digests, HTTP readiness, and post-teardown process reaping;
a non-zero teardown status or leaked process makes an otherwise successful run
exit non-zero too.

`health` must query the live installed Server and built-in Endpoint, not read
the release pointers or a cached manifest. Its successful JSON result contains
`health: { status: "ok", source: "live_process", checks: { ui: "ok",
server: "ok", endpoint: "ok" }, ui_mode: "assets",
ui_assets_directory: "ui", revision, components }`; the installed Server
configuration must resolve that `ui_assets_directory` relative to its config
file and must not use `api_only`. Each component revision and digest must
match the expected immutable artifact. It must also include
`health.probes.server_url` and `health.probes.endpoint_url` on local HTTP
readiness listeners. The harness performs fresh HTTP probes, captures and
parses the real `zode.system.v1` and `zode.endpoint-health.v1` response bodies,
and binds the Server UI listener and `/v1/system` port to the independently
observed live Server PID (and `/v1/health` to the Endpoint PID); it does not
treat the driver's JSON health claim as readiness evidence. The
known health-failing fixture must return non-zero with the same shape but a
non-`ok` status/check, and must identify the failed artifact.
The failed-stage Server/Endpoint PIDs, immutable executables, listener ports,
and HTTP bodies are independently observed before the baseline health check;
all PIDs observed in either successful or failed staging are rechecked after
teardown.
Process identity is consumed from `health.processes.locator_paths`, whose files
must use the exact `zode.e2e.process-locator.v1` contract. Production processes
do not write these files: the driver creates test-owned locators only after
binding the Server PID/parent process group and its one known Endpoint child
by exact installed executable/argv/config/listen, listener ownership, and
authenticated identity/capabilities. The harness never binds a release
instance by scanning unrelated same-name processes. Teardown must return one
or more exact `zode.e2e.process-stop.v1` reports; each `observed_pids` entry
includes the PID, role, process-group/session identity, executable path, and
SHA-256 digest, while `reaped_pids`/`leaked_pids` contain only those observed
PIDs. Every observed instance and PID must be accounted for.

The browser portion only starts after a real management page returns a
successful document response. It verifies the product's existing management
shell and normal Access-protected UI → Server → built-in Endpoint path;
promotion and rollback are operator driver actions, not browser controls.
The browser must receive successful `zode.system.v1`, `zode.endpoints.v1`, and
`zode.providers.v1` responses through the same origin, and the endpoint catalog
must contain the `local_endpoint_id` from `zode.system.v1`; these are existing
management routes, not release metadata APIs.
The product is not required to expose release pointers, component digests, or
test-only DOM markers. The harness independently reads the selected manifest
and `current`/`previous` pointers, hashes the served UI tree, and binds the
observed Server/Endpoint PIDs to their executable digests.
The test first stages the health-failing build and proves that `current` does
not change, then stages the candidate and proves it still does not change.
The operator driver then promotes it. During promotion the harness watches the
real release-root filesystem and requires a positive event showing the
canonical before and after pointer states; a torn or unparsable
`current`/`previous` fails the scenario. Only `rename`/`change` events whose
filename is exactly `pointer-state` (the atomic transaction link) count; a
legacy direct-pointer event is accepted only when its post-event pair is also
canonical. Both pointer names must be observed after the action.
It then invokes operator rollback, reloads the browser entry, and proves that the
baseline is current again, the candidate is previous, and browser runtime
document still loads through the normal path after reload. Packaged UI, Server, and
Endpoint payloads are immutable, hashed before staging, and re-hashed after
teardown so a driver cannot mutate the staged payload in place.

The named acceptance cases are
`e2e_release_artifact_binds_server_endpoint_and_ui_tree` (manifest and
immutable component binding) and
`e2e_release_promotion_never_mixes_server_and_ui_revision` (real health,
browser promotion, torn-pointer observation, rollback, and reload).

Exit codes:

- `0`: the real release/browser path passed;
- `1`: a semantic E2E failure was observed;
- `78`: blocked before a valid public path existed (missing build surface,
  release driver, or a shallow HTTP/compile failure). This is not a behavioral
  red and is never promoted to a cassette.

For a semantic failure, the harness writes the first post-rule exchange to a
`0700` directory under `target/test-recordings/quarantine/<run-id>` (or the
explicit `ZODE_RELEASE_QUARANTINE` test override). `--promote-incident` creates
one new `zode.http-incident-recording.v1` cassette under this suite's
`fixtures/incidents/` (or the explicit `ZODE_RELEASE_CASSETTES` test override)
with exclusive creation,
allowlisted headers, synthetic slots, an exact binding to the first captured
failing browser exchange, a whole-envelope SHA-256, and mode `0444`. Secret
scanning is fail-closed, including configured secret values, headers, all
recorded fields, and decoded bodies. It never overwrites an existing cassette.
`--replay <cassette>` (with `ZODE_RELEASE_REPLAY_EXPECTATION=red` before a
repair or `green` after it) validates its unique exact `exchange_sequence`, passes
that same immutable cassette through a test-owned replay adapter (never to the
production driver), and repeats the same browser entry. Before the production
repair the replay must reproduce the exact sequence and exchange fingerprints,
including the original request query, `requestfailed`, and disconnect markers;
after the repair the same cassette and named E2E must pass. Cassette body values
must be canonical
RFC 4648 base64 before secret scanning. The raw quarantine and cassettes are
never production inputs.

If a failure occurs before the browser entry (for example, a staged payload
mutation), a real-driver semantic failure is RED and the exact raw
release-driver exchange is still retained, but no browser cassette is promoted
for it; replay is reserved for a captured browser-bound failure. A missing
driver or missing public seam remains BLOCKED.

The harness does not make an LLM request. If the real release path adds one,
the release driver must route it through the test-owned recorder mandated by
`docs/test-recording.md`; a direct provider URL is outside this E2E's scope.

Immutable-source premise: the harness obtains every candidate source with
`git archive` of its canonical commit; it never copies a dirty candidate
worktree or fills an archive from uncommitted files. Every revision must carry
the complete tracked build surface, including the release driver path. A
revision missing that surface remains `78` BLOCKED even if the dirty worktree
happens to contain the files; the harness must not copy them or create a
fabricated 404/compile cassette.
