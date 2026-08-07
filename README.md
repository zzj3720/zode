# zode

一个由管理 Server、设备 Endpoint 和 Web UI 组成的持久化 agent 系统。

总体架构见 [`docs/architecture.md`](docs/architecture.md)，Endpoint runtime
见 [`docs/design.md`](docs/design.md)，Endpoint API 见
[`docs/http-api.md`](docs/http-api.md)，Server/UI API 见
[`docs/server-api.md`](docs/server-api.md)，认证复制见
[`docs/auth-replication.md`](docs/auth-replication.md)，管理入口认证见
[`docs/access.md`](docs/access.md)，开发和 review 规则见 [`AGENTS.md`](AGENTS.md)。

Endpoint 只负责设备上的 session、工具、工作区和 provider 执行，不主动连接
Server。Server 统一管理 provider 登录和 auth profile，并向选定 Endpoint 分发
版本化凭证副本。Endpoint 通过本地 aimux 直接请求 provider。Server 可附带一个
使用同一 HTTP/SSE 协议的本机 Endpoint，作为单机默认部署。

Zode v0 不实现用户、角色、登录页或登录 Cookie；Web UI 和管理 API 统一由
Cloudflare Access 保护。所有被同一个 Access 应用放行的身份共享管理资源，
Endpoint 则按 Access 身份派生的匿名 subject 隔离各自 session。外部工具 callback
使用独立公开入口和一次性 bearer，不依赖浏览器 Access 会话。

Endpoint 自己持有稳定 `endpoint_id`，Session 也完全由 Endpoint 创建和持久化：
Endpoint 生成 ULID，外部使用 `(endpoint_id, session_id)` 定位。Server 不创建、
不映射、不镜像、也不持久化 session，只做鉴权和实时 HTTP/SSE 代理。

项目从自身的公开行为和 E2E 契约出发实现，不移植 Codex 生产代码或测试。默认
持久化使用 SQLite，但 Server、Endpoint runtime 和各存储适配器保持可替换。

## 测试原则

仓库只允许真实进程 E2E：Endpoint 测试启动实际 Endpoint；系统测试启动真实
Server 和 Endpoint；UI 测试使用真实浏览器。全部通过公开 HTTP/SSE 使用产品。
禁止单元测试、白盒集成测试、组件测试和隐藏测试入口。
