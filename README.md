# ITOM Mini — Backend (Phase 1 + Phase 2 reliability)

NestJS API plus Postgres ingest, and a Go agent that collects host metrics, buffers them locally (SQLite), and flushes batches to the API. The parent repo root may include a `frontend/` folder for the UI.

```
Laptop A (API)                       Laptop B / C / ... (agent)
┌─────────────────────────┐          ┌──────────────────────────┐
│ NestJS (backend/BE)     │ ◀─POST── │ Go binary (gopsutil)     │
│   POST /v1/metrics      │          │  config: ~/.itom-agent/  │
│   GET  /v1/metrics      │          │  log:    ~/.itom-agent/  │
│   GET  /v1/metrics/agents│         └──────────────────────────┘
│   /v1/agents/...        │
│   GET  /v1/health       │
│        ↓                │
│ Postgres (local)        │
│   db: itom              │
└─────────────────────────┘
        port 3000                              no inbound port
```

## Folder layout

From the repository root (`Code/`):

```
Code/
├── backend/                         ← this document
│   ├── BE/                          NestJS + TypeORM + PostgreSQL
│   │   ├── src/
│   │   │   ├── main.ts              bootstrap, global prefix `v1`, CORS, `0.0.0.0`
│   │   │   ├── app.module.ts        TypeORM + entity registration
│   │   │   ├── health/              GET /v1/health
│   │   │   ├── metrics/             ingest + list metrics, list reporting agents
│   │   │   └── agents/              agent registration, list/detail, binary/install routes
│   │   ├── agents-dist/             optional: pre-built agent binaries + install.sh
│   │   ├── package.json
│   │   ├── .env.example
│   │   └── tsconfig.json
│   └── agent/                       Go agent (Go 1.22+)
│       ├── cmd/agentd/main.go     run loop, signal handling
│       ├── internal/
│       │   ├── config/              ~/.itom-agent/config.json (auto-created)
│       │   ├── buffer/              SQLite FIFO at ~/.itom-agent/buffer.db
│       │   ├── collector/           CPU / memory / disk (+ optional network/disk detail)
│       │   ├── sender/              POST /v1/metrics + /v1/agents/heartbeat
│       │   ├── logger/              slog → stderr + ~/.itom-agent/agent.log
│       │   └── info/                host metadata for registration
│       ├── go.mod
│       ├── Makefile                 build / build-all / clean (Unix)
│       └── build.ps1                Windows helper for builds (optional)
└── frontend/                        UI (separate app; may be empty in early phases)
```

---

## Prerequisites

**API machine:**

- Node.js 20+ and npm
- PostgreSQL 14+ (same install notes as before: Homebrew, apt, Windows installer, or Postgres.app)

**Agent build machine:**

- Go 1.22+ to compile; target hosts only need the compiled binary.

---

## One-time PostgreSQL setup

Create database `itom` and user `itom` (adjust names/passwords to match `backend/BE/.env`):

```sql
CREATE USER itom WITH PASSWORD 'itom';
CREATE DATABASE itom OWNER itom;
GRANT ALL PRIVILEGES ON DATABASE itom TO itom;
\q
```

Verify:

```bash
psql -h localhost -U itom -d itom -c '\conninfo'
```

If authentication fails on Linux, see peer vs md5/scram notes in the original project docs; update `.env` or `pg_hba.conf` accordingly.

TypeORM `synchronize: true` creates and updates tables (`metric`, `network_metric`, `disk_metric`, `agent`, etc.) on startup — you do not hand-create the schema for local dev.

---

## Run the API

```bash
cd backend/BE
cp .env.example .env           # edit DB_* if needed
npm install
npm run start:dev              # default 0.0.0.0:3000, hot-reload
```

Expected log line:

`ITOM server listening on 0.0.0.0:3000`

### Verify

```bash
curl http://localhost:3000/v1/health
# {"status":"ok","time":"2026-..."}
```

### LAN IP and firewall

Agents need `http://<SERVER_IP>:3000`. Discover IP the same way as before (e.g. `ipconfig` on Windows, `ipconfig getifaddr en0` on macOS). Open inbound TCP 3000 on the API host if a firewall blocks it.

---

## Build the agent

```bash
cd backend/agent

# Current OS → backend/agent/dist/itom-agent
make build

# All common platforms
make build-all
ls dist/
# itom-agent-linux-amd64, itom-agent-linux-arm64, …
```

On Windows without Make, use `build.ps1` if present, or invoke `go build` similarly to the Makefile targets.

Static binaries can be copied to `backend/BE/agents-dist/` so the API can serve them from `/v1/agents/download/:filename` (set `AGENTS_DIST_PATH` if you store them elsewhere).

---

## Run the agent

First run — point at the server:

```bash
# Linux / macOS
ITOM_SERVER_URL=http://<SERVER_IP>:3000 ./dist/itom-agent

# Windows (PowerShell)
$env:ITOM_SERVER_URL="http://<SERVER_IP>:3000"
.\dist\itom-agent-windows-amd64.exe
```

Config, logs, and the SQLite metric buffer live under `~/.itom-agent/` (or `%USERPROFILE%\.itom-agent\` on Windows). Subsequent runs pick up `serverUrl` and reliability knobs from `config.json` unless you override env vars on first-run creation (`ITOM_SERVER_URL`, `ITOM_INTERVAL_SECONDS`).

Useful flags: `-version`, `-config <path>`.

---

## Verify end-to-end

```bash
curl http://localhost:3000/v1/metrics/agents
curl 'http://localhost:3000/v1/metrics?limit=10'
curl 'http://localhost:3000/v1/metrics?agentId=<uuid>&limit=10'
```

Direct SQL (identifiers may be snake_case in DB; quote if needed):

```bash
psql -h localhost -U itom -d itom -c 'SELECT * FROM metric ORDER BY timestamp DESC LIMIT 5;'
```

---

## API summary

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/v1/health` | Liveness |
| POST | `/v1/metrics` | Ingest metric batches from agents |
| GET | `/v1/metrics` | Recent samples (`agentId`, `limit` query params) |
| GET | `/v1/metrics/agents` | Agents seen via metrics ingest |
| POST | `/v1/agents/register` | Register/update agent metadata |
| POST | `/v1/agents/heartbeat` | Liveness + uptime (separate from metrics flush) |
| GET | `/v1/agents` | List registered agents |
| GET | `/v1/agents/:agentId` | Agent detail |
| GET | `/v1/agents/install.sh` | Served from `agents-dist/install.sh` if present |
| GET | `/v1/agents/download/:filename` | Whitelisted pre-built binaries from `agents-dist` |

### POST `/v1/metrics` body (shape)

Core fields per sample: `timestamp` (ISO-8601), `cpuPercent`, `memoryPercent`, `diskPercent` (0–100). Optional fields include `memAvailableBytes`, `loadAvg1m`, `processCount`, `network[]` (per-interface counters), and `disks[]` (per-mount usage). Optional top-level `requestId` (UUID v4) mirrors the `X-Request-Id` header for idempotency. See `backend/BE/src/metrics/dto/create-metrics.dto.ts` for validation rules.

### POST `/v1/agents/heartbeat` body (shape)

`agentId` (UUID), `timestamp` (ISO-8601), optional `agentVersion`, optional `uptimeSeconds` (non-negative integer). Send header `X-Request-Id` (UUID v4) for deduplication; duplicate heartbeats return `{ "accepted": false, "reason": "duplicate" }` with HTTP 200.

### POST `/v1/agents/register` body (shape)

Requires `agentId` (string). Optional metadata: `hostname`, `os`, `arch`, IP lists, MAC addresses, CPU/memory/disk totals, etc. See `backend/BE/src/agents/dto/register-agent.dto.ts`.

---

## Agent execution flow (conceptual)

```
START
  ├─ load ~/.itom-agent/config.json (create with new UUID if missing)
  ├─ open ~/.itom-agent/buffer.db (SQLite WAL)
  ├─ register once with /v1/agents/register
  ├─ goroutine: collect every intervalSeconds (±25% jitter) → Append(sample)
  ├─ goroutine: flush every flushSeconds OR when buffer ≥ maxBatchSize → POST /v1/metrics (batched)
  ├─ goroutine: heartbeat every heartbeatSeconds → POST /v1/agents/heartbeat
  └─ SIGINT/SIGTERM → cancel workers → best-effort final metrics flush (5s deadline) → exit
```

---

## Agent ↔ Server connection (Phase 2 reliability)

**One-line summary:** samples are **collected on a fixed cadence**, written to a **local SQLite buffer** (`~/.itom-agent/buffer.db`), then **flushed in batches** to `POST /v1/metrics` with a per-batch **`X-Request-Id`**; on HTTP **2xx** the agent **deletes** those rows from the buffer. **Heartbeats** are a separate POST on their own timer and are **not** buffered.

### Configurable knobs (`~/.itom-agent/config.json`)

| Field | Default | What it controls |
|--------|---------|------------------|
| `intervalSeconds` | `10` | How often the collector runs (±25% jitter). Each tick appends **one** sample to SQLite. |
| `flushSeconds` | `60` | How often the sender tries to drain the buffer (±25% jitter), **unless** `maxBatchSize` is reached first. |
| `heartbeatSeconds` | `30` | How often the heartbeat goroutine POSTs `/v1/agents/heartbeat` (±25% jitter). |
| `maxBatchSize` | `60` | Maximum samples per metrics POST; also signals an **immediate** flush attempt when the buffer reaches this count. |
| `maxBufferRows` | `50000` | Hard cap on SQLite rows; oldest rows are **dropped** (warn logged) if exceeded. |

### Retries and backoff

- On **network errors**, **HTTP 429**, or **5xx**, the batch **stays in SQLite** and the sender applies **exponential backoff**: starting at **5s**, doubling each failure, **capped at 5 minutes**, with **±25% jitter** on every wait (including the normal flush timer spacing).
- On **HTTP 4xx other than 429**, the batch is considered **non-retryable**: it is **removed** from the buffer and logged as an error (so a permanently bad payload cannot block the queue forever).

### Idempotency (`X-Request-Id` + `request_dedup`)

- Each metrics flush generates a **fresh UUID v4** sent as **`X-Request-Id`** and duplicated in the JSON body as **`requestId`** (optional but recommended).
- The API records that id in **`request_dedup`**. If the same id arrives twice (client retry after timeout), the second call returns **`{ "accepted": 0, "reason": "duplicate" }`** and performs **no** inserts — the agent still treats this as success and **deletes** the batch from SQLite (the data is already stored).
- Heartbeats use the same header + `request_dedup` with endpoint `heartbeat`.
- A background job **prunes** `request_dedup` rows older than **1 hour** (every **15 minutes**).

### What happens when things fail

**If the server is down:** samples keep accumulating in `buffer.db`. When the server returns, backoff cools down and the backlog drains in batches.

**If the agent crashes or the machine reboots:** `buffer.db` survives on disk; on the next start the agent logs how many samples are pending and the sender drains them.

**If the machine is lost permanently:** anything not yet flushed is gone. The API marks agents **offline** if **`lastSeenAt`** is older than **90 seconds** (no metrics **and** no heartbeat). `agents.lastSeenAt`, `agents.status`, and `agents.statusChangedAt` reflect that transition (cron every **30s**).

### Flush on shutdown (SIGINT / SIGTERM)

Workers are cancelled, then the agent performs **one** best-effort metrics flush with a **5-second** HTTP deadline. If it succeeds, those SQLite rows are removed. If it fails, rows remain for the **next** process start.

### Heartbeats vs metrics

Heartbeats are **not** spooled to SQLite. They run on **`heartbeatSeconds`** and update **`agent_heartbeats`** plus **`agents.lastSeenAt`**. Missed heartbeats are tolerated up to the **90s** server offline threshold.

### Honest limits (not handled)

- If the buffer hits **`maxBufferRows`**, **oldest** samples are dropped to cap disk use.
- If the agent disk is full, buffering fails.
- A **kernel panic** mid-write can still corrupt or lose the last fraction of a second of buffered data (SQLite WAL mitigates but does not eliminate this).

### Troubleshooting (reliability)

| Question | How to check |
|----------|----------------|
| How many samples are pending locally? | `sqlite3 ~/.itom-agent/buffer.db "SELECT COUNT(*) FROM samples;"` (Windows: same path under your user profile). |
| Is the server marking my agent online/offline? | `psql ... -c 'SELECT "agentId", hostname, status, "lastSeenAt", "statusChangedAt" FROM agents;'` |
| Did I get a duplicate dedupe response? | Re-send the same `curl` to `/v1/metrics` with an identical `X-Request-Id` — second call should return `"reason":"duplicate"`. |

---

## Troubleshooting

| Symptom | Likely fix |
|---------|------------|
| `ECONNREFUSED` to Postgres | Start Postgres; check `DB_HOST` / `DB_PORT` |
| Password auth failed | Fix `DB_USER` / `DB_PASSWORD` in `.env` |
| Database missing | Create `itom` database and owner |
| Agent connection refused | API listening on `0.0.0.0`, firewall, same network |
| `400` on metrics | Check server logs; validate payload against DTO |
| `404` on install/binary download | Populate `backend/BE/agents-dist/` or set `AGENTS_DIST_PATH` |
| Reset dev data | Stop API, drop tables or database, restart (TypeORM recreates schema) |

---

## Environment variables (`backend/BE`)

| Variable | Purpose |
|----------|---------|
| `PORT` | HTTP port (default `3000`) |
| `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` | PostgreSQL connection |
| `DB_LOGGING` | `true` to log SQL |
| `AGENTS_DIST_PATH` | Optional absolute path to folder containing `install.sh` and agent binaries for download routes (defaults to `agents-dist` under `BE`) |
