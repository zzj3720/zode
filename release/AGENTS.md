# Release driver and local test-channel rules

`release/` owns the immutable artifact installer used by the local test
channel.  The driver is an operator-facing composition boundary: it validates
the harness manifest, installs a complete artifact atomically, starts the
all-in-one Server for its own release instance, binds its one known Endpoint
child, exposes live health metadata, and stops and reaps that instance on
teardown.

## 固定本机测试通道入口

从干净 checkout 构建一个 revision 后，`release/channel.cjs` 提供稳定的
build/install/start/stop/update 入口：

```sh
node release/channel.cjs build --revision <commit> --output-root <artifact-root>
node release/channel.cjs install --artifact <artifact> --release-root <channel-root>
node release/channel.cjs start --artifact <artifact> --release-root <channel-root>
node release/channel.cjs stop --release-root <channel-root>
node release/channel.cjs update --artifact <candidate> --release-root <channel-root>
```

`install` 只把不可变 revision 原子写入 `releases/`，不改变 `current` 或
`previous`。空通道的 `start` 只有在真实 readiness gate 通过后才建立
`current`；已有通道的 `start` 执行 live health。`update` 先 stage 并观察
candidate，再调用 operator promotion；stage 失败时报告 `current`/
`previous` 是否保持不变且不会继续 promotion。`stop` 委托 driver 的有界
teardown，任何泄漏或 flush 失败都会返回非零。该入口不接受 cassette、replay、
recorder、locator 或未认证 health 参数。

需要把测试版交给本机用户时，使用 `release/local-channel.cjs` 建立可留存的
默认通道 `~/.zode/test-channel`（也可传 `--channel-root`）：

```sh
node release/local-channel.cjs install --artifact <artifact>
node release/local-channel.cjs start
node release/local-channel.cjs status
node release/local-channel.cjs stop
```

`start` 输出固定本机浏览器 URL；同一根目录中的不可变 artifact、Endpoint/
Server 持久状态和本地 Access edge 配置会在 stop/start 后保留，用户不需要
拼接临时进程。该 edge 只是测试通道的真实 Access 签名转发器，不是 Server
的未认证 fallback；它不记录请求、不接受 cassette/replay，也不进入产物中的
Server/Endpoint 进程。若要在 UI 中配置外部 provider，启动时用不含凭据的
`ZODE_RELEASE_PROVIDER_ORIGINS=https://<approved-provider-origin>` 声明允许的
origin；provider key 仍只在 Access-protected UI 的 profile 表单中输入。
edge 与它的管理上游都固定为 `127.0.0.1` HTTP loopback；篡改私有状态使其
监听其它地址或把 Access assertion 转发到非 loopback origin 时，入口必须
fail closed。`open` 在健康失败或无法启动系统浏览器时会回收本次 edge，不能
留下 runtime 指针或 detached 进程。`update` 在 fresh 根或候选 admission
失败时也必须回收本次启动的 edge/runtime；已有健康通道更新失败时保留原
edge，避免把仍可用的 current 通道一并停掉。

外部 artifact 的 `install`/`bootstrap`/`stage` admission 先由 checkout 中的
受信 driver 校验 manifest、组件 digest 和不可变树；不会先执行 artifact 自带
的脚本。安装成功后，`promote`、`health` 和 `teardown` 才从 `current` 读取
已安装且 digest 绑定的 driver。

本机通道要求 artifact 的 `release-driver` digest 与执行 admission 的同一
干净 checkout `release/driver` 相等；这样即使攻击者重新签出一份自洽
manifest，也不能把未知脚本带进通道。

`health`/`teardown` 执行前还会由 checkout 中的受信 driver 对 `current` 的
完整 artifact 重新做一次 admission，并要求它精确落在本通道的
`releases/` 安装树；仅有自洽 envelope 或 driver 字段的伪造目录不可执行。
如果 current 已安装但尚未有 live release instance，health 返回结构化失败
状态，供 start/recovery 入口继续处理，不把缺失运行态变成 CLI 崩溃。

The driver does not implement Server or Web release-control resources.  The
operator driver/CLI performs promotion and rollback; the browser only verifies
the ordinary Access-protected UI → Server → built-in Endpoint path afterwards.
The driver must not accept cassettes, replay paths, recorder flags, or
unauthenticated health fallbacks.  Test-only recording and replay belong to
`tests/release_e2e/**` and the shared recorder seam.

Every artifact is immutable and binds one source revision to the UI tree,
Server binary, Endpoint binary, protocol inputs, and driver digest.  Staging
starts and observes the candidate on isolated listeners without changing
`current` or `previous`; only a separately approved promotion operation may
change those pointers.  Process identity is scoped to a run-owned instance
locator and is independently checked by the release E2E with OS executable,
listener, HTTP, and digest evidence.

All mutating driver operations serialize through one release-root operation
lock.  A stale lock is reclaimed only when its recorded owner PID is no longer
alive; a live or malformed lock fails closed.

Release-instance directories are disposable process/config state only.  The
active `current` instance uses one run-owned persistent Endpoint runtime store,
Server control database, subject key, controller authority secret, and Server
secret directory; promotion and rollback point the replacement process at
those same paths, so Endpoint identity, catalog, sessions, and credentials do
not reset.  A `candidate` instance deliberately receives an isolated store,
authority, and secret directory while it is staged, otherwise its SQLite
ownership locks and catalog would conflict with the active release.  The
candidate's persistent state is discarded with that instance after promotion
or failed staging.

The driver may use the existing Access assertion and Endpoint controller-auth
configuration supplied by the local test channel.  It must never emit their
values or persist them in manifests, release pointers, ordinary logs, or
health JSON.  Production Server/Endpoint processes do not import the test
process seam or write locator files; the driver derives a test-owned Endpoint
locator only after validating the Server's known direct child by PID/parent,
exact installed argv/config/listen, executable digest, listener, and
authenticated identity/capabilities evidence.
