# AGENTS.md — ssh-fleet Architecture & Engineering Guide

Guidelines for coding agents working in `ssh-fleet`. Keep commits, docs, and comments free of personal IPs, emails, SSH aliases, or tokens (public repository).

## 1. Architecture & Constraints
- **Pure Go 1.22 stdlib**: `go.mod` has zero third-party dependencies. Keep it dependency-free (`net/http`, `crypto/*`, `encoding/*`, custom RFC 6455 `internal/ws`).
- **Single embedded Web UI**: [internal/hub/web/index.html](internal/hub/web/index.html) embedded via [internal/hub/web.go](internal/hub/web.go). Keep inline JS valid vanilla script (no build step).
- **Package map**:
  - `cmd/sf`: CLI entrypoint (`sf`), Hub/Agent service installers (`hub --install-service`, `join`), self-updater command (`update`).
  - `internal/hub`: Relay Hub HTTP/WS server, node registry, join tokens, Cloudflare Access verifier, IP rate limiter, Web UI.
  - `internal/agent`: Persistent reverse-tunnel client, local SSH/PTY shell streamer, power actions, GNOME keyring unlock.
  - `internal/ws`: Custom RFC 6455 WebSocket client/server (`UpgradeServerWithOptions`, `DialClient`, `UpgradeError`).
  - `internal/protocol`, `internal/updater`, `internal/version`, `internal/vault`, `internal/crypto`, `internal/power`, `internal/keyring`, `internal/wol`, `internal/ui`, `internal/fuzzy`.

## 2. Auth & Peer-Trust Model (Intentional — Do Not Break)
This is a **personal peer-trust fleet**: all enrolled devices belong to one owner and share one Web control surface.
- **`authNode` (`sfn_<nodeID>.<secret>`, issued via `/api/v1/join/exchange`)**:
  - Intentionally allowed across nodes: `GET /api/v1/nodes`, `POST /api/v1/nodes/:id/power` (only when `keyring_password == ""`), `GET /tunnel/client-proxy`, and `GET`/`PUT /api/v1/vault`.
  - **Do not** restrict `/api/v1/nodes/:id/power` (without `keyring_password`) or `/tunnel/client-proxy` to `authAdmin` or self-only unless explicitly requested.
- **Identity binding (`boundNodeID`)**:
  - `/tunnel/control`: `authNode` may register only `node_id == boundNodeID`.
  - `/tunnel/agent-stream`: `authNode` may attach only to pending streams owned by `boundNodeID` (`403` otherwise).
- **`authAdmin` only (`sf_...` Hub token or verified Cloudflare Access admin)**:
  - `POST /api/v1/nodes/:id/unlock-keyring`, `POST /api/v1/nodes/:id/power` when `keyring_password != ""`, `PATCH`/`DELETE /api/v1/nodes/:id`, `PATCH /api/v1/nodes/:id/wol`, `POST /api/v1/nodes/:id/update`, `/api/v1/hub-info`, `/api/v1/join-tokens`, `/api/v1/wake-relays*`, and `/api/v1/ws/terminal`.

## 3. Security & Wire Invariants
- **Web UI auth**: `POST /api/v1/auth/login` sets an `HttpOnly`, `SameSite=Lax` cookie `sf_token` (`Secure` on HTTPS). Never re-introduce `localStorage` token storage or `?token=` query authentication. `/api/v1/ws/terminal` enforces `sameHostOriginCheck`.
- **Rate limiting**: `auth/login` and `join/exchange` are rate-limited (`ipRateLimiter`: 10/min/IP -> `429`).
- **Cloudflare Access**:
  - Prefer RS256 JWKS (`--cf-access-team` + `--cf-access-aud`). Partial verifier config fails closed (`NewServerWithOptions` error); when verifier is active, never fall back to raw `Cf-Access-Authenticated-User-Email`.
  - Legacy header-only mode (`--trust-cf-access` without verifier) trusts loopback `RemoteAddr` (`127.0.0.1` / `::1`) only. When CF Access is enabled without explicit `--listen`, `cmdHub` defaults `--listen` to `127.0.0.1:8090`.
- **Validation & atomic writes**:
  - `ValidateNodeID` enforces `1..64` chars matching `[a-zA-Z0-9][a-zA-Z0-9_-]*` (no `.` for unambiguous `sfn_<nodeID>.<secret>`, no leading `-` to avoid SSH option injection). Online collision returns `409` before consuming join tokens.
  - `writeFileAtomic` writes credentials, registries, node state, and `vault.enc` (`SFV1` envelope check + `vault.enc.bak`). `sf hub --install-service` writes secrets to `0600` `<dataDir>/hub.env` (`EnvironmentFile=`) instead of CLI `--token` flags.
- **Wire lifecycle**:
  - `sendAndWait` uses per-agent `pendingReq` maps; control-tunnel eviction sends `"replaced"` outside `s.mu` (agent holds reconnect 20s).
  - Agent dial/upgrade failures send `"stream-error"` so Hub proxy returns fast HTTP `502`.
  - `spliceConns` / `spliceBuffered` call `Close()` when a destination lacks `CloseWrite()` (e.g., `*ws.Conn`).
  - Shell stream shutdown waits on `stdinDone` / kills stuck child after brief grace before `cmd.Wait()`.

## 4. Release & Deploy Flow
- Use Conventional Commits. Pushing an annotated tag `vX.Y.Z` triggers [.github/workflows/release.yml](.github/workflows/release.yml) -> `go test -race ./...` & `go vet ./...` -> cross-builds 5 binaries (`linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`) + `SHA256SUMS.txt` -> publishes GitHub Release.
- Running Hub & Agent binaries check GitHub Releases every 30m via `updater.StartAutoLoop` (unless `--auto-update=false` or `SF_AUTO_UPDATE=0`), verify SHA-256 against `SHA256SUMS.txt`, atomically swap the binary, and restart `systemd --user` / system units or macOS LaunchAgent (`sf update` triggers this immediately).

## 5. Verification & Test Pitfalls
Run before finishing any change:
```bash
go test -race -count=1 ./...
go vet ./...
GOOS=linux GOARCH=amd64 go build ./... && GOOS=windows GOARCH=amd64 go build ./...
node -e 'const fs=require("fs"),vm=require("vm"); const h=fs.readFileSync("internal/hub/web/index.html","utf8"); h.match(/<script>([\s\S]*?)<\/script>/g).forEach((s,i)=>new vm.Script(s.replace(/^<script>|<\/script>$/g,""),{filename:"s"+i}));'
```
- **Test pitfalls in `internal/hub/hub_test.go`**:
  - Agent teardown runs asynchronously (`handleControlTunnel` writes `hub-nodes.json` via `writeFileAtomic` on disconnect). Always cancel agent `ctx`, await `ag.Run` completion, and `waitForNodeOnline(t, srv, id, false, ...)` before `t.TempDir()` cleanup runs.
  - Set `IsVPS: &notVPS` (`notVPS := false`) in tests covering sleep/poweroff so CI VM/container environments do not reject power commands via `DetectIsVPS()`.
