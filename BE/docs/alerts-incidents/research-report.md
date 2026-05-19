# Alerts & Incidents Module — Research Report

> Status: **Research / proposal** — not yet implemented.
> Audience: ITOM portal team. Decide on the model, then we build it.
> Date: 2026-05-15

---

## 1. Executive summary

The ITOM portal currently has **no real alerting**. The dashboard's "Latest
incidents" card is a cosmetic derivation — it just lists agents whose
`status` is not `online` (see `frontend/src/components/itom/dashboard/incidents-card.tsx`).
There is no rule engine, no thresholds, no alert history, and no incident
record. Nothing fires when a disk fills up or a CPU pegs at 100%.

This report:

1. Inventories **what data we already capture** from agents (Section 3).
2. Summarises **how established platforms** do alert generation and incident
   collection (Section 4).
3. Proposes a **concrete threshold catalog** for the metrics we have (Section 6).
4. Proposes a **data model + evaluation engine** that fits the existing NestJS
   backend (Sections 7–9).
5. Lays out a **phased implementation plan** and the portal UI (Sections 10–11).

The recommended model is the industry-standard pipeline:

```
metric sample  →  alert rule (threshold + duration)  →  alert (stateful)  →  incident (correlated, deduplicated)
```

---

## 2. Goals & non-goals

**Goals**
- Detect unhealthy states from agent telemetry automatically.
- Avoid alert noise (flapping, duplicates, transient spikes).
- Group related alerts into a single incident a human can act on.
- Per-tenant configurable thresholds with sensible defaults out of the box.
- Surface everything on the ITOM portal: live alerts, incident timeline, rules.

**Non-goals (for v1)**
- External notifications (email/Slack/PagerDuty) — design for it, ship later.
- On-call scheduling / escalation policies.
- Anomaly detection / ML baselining — start with static + simple dynamic thresholds.
- Auto-remediation.

---

## 3. What we capture today (the raw material)

Agents (`backend/agent`, Go daemon) collect on a **10s interval**, buffer to
on-disk SQLite, and flush batches every **60s**. The backend marks an agent
`offline` if `lastSeenAt` is older than **90s** (`agents-scheduler.service.ts`).

### 3.1 Core system metrics — table `metrics`
| Field | Type | Unit | Alertable? |
|---|---|---|---|
| `cpuPercent` | double | 0–100 | ✅ utilisation |
| `memoryPercent` | double | 0–100 | ✅ utilisation |
| `diskPercent` | double | 0–100 | ✅ utilisation (root volume) |
| `memAvailableBytes` | bigint | bytes | ✅ low-memory absolute floor |
| `loadAvg1m` | double | load | ✅ (normalise by `cpuCores`) |
| `processCount` | int | count | ⚠️ weak signal, runaway-process hint |

### 3.2 Per-volume disk — table `disk_metrics`
`usedPercent`, `usedBytes`, `totalBytes` **per mountpoint**. ✅ The right
source for disk alerts — per-volume, not just the root `diskPercent`.

### 3.3 Network — table `network_metrics`
`bytesSent/Recv`, `packetsSent/Recv` **per interface**. ⚠️ **These are
cumulative counters**, not rates. The evaluation engine must compute a
delta between consecutive samples (`Δbytes / Δseconds`) before it can
threshold throughput. A counter reset (reboot, NIC re-init) shows as a
negative delta and must be discarded.

### 3.4 Observability metrics
| Table | Fields | Alertable signals |
|---|---|---|
| `process_metrics` | name, pidCount, cpuPercent, memoryBytes, io* | ✅ per-process CPU/mem hog |
| `battery_metrics` | percent, charging, onAC, healthPercent, cycleCount | ✅ battery health degraded, critically low |
| `gpu_metrics` | utilizationPercent, memoryUsed/Total, temperatureC, powerWatts | ✅ GPU temp / saturation |
| `sensor_metrics` | name, kind (`temperature_c`/`fan_rpm`), value | ✅ thermal, fan failure (0 RPM) |
| `software_item` | name, version, publisher | ⚠️ inventory-change / blocklist alerts (later) |

### 3.5 Availability — table `agent_status_events`
One row per `online↔offline` transition. ✅ The cleanest availability
signal — "agent went offline" is itself an alert condition (no threshold
needed).

### 3.6 Gaps worth noting
- **No event/log stream** from agents — alerting is metric-only for now.
- **No "expected fleet" notion** — we can detect an agent that *was* online
  going offline, but not a machine that should exist and never registered.
- Network counters need rate derivation (above).
- CPU is a single 500ms sample every 10s — fine for sustained load, blind
  to sub-second spikes (acceptable).

---

## 4. How other ITOM / monitoring platforms do it

Common pipeline across **Prometheus/Alertmanager, Datadog, Zabbix, PRTG,
NinjaOne RMM, ServiceNow ITOM, PagerDuty**:

### 4.1 Alert *generation* (signal → alert)
- **Rule = condition + duration.** A threshold breach alone never fires. It
  must persist for a configured window ("for" in Prometheus, "retest window"
  in Google Cloud Monitoring, "time-based dampening" in RMM tools). Typical:
  CPU must stay above 95% for **3–5 minutes** before a ticket is cut. This
  kills transient-spike noise.
- **Severity tiers.** `info / warning / critical` (Datadog, Zabbix's 6-level
  scale, PagerDuty's P1–P5). Each tier usually has its own threshold —
  warning at 80%, critical at 95%.
- **Hysteresis / recovery thresholds.** An alert clears at a *lower* value
  than it fired at. Datadog "recovery thresholds": fire at 95%, recover at
  85%. Prevents **flapping** — the alert toggling on/off around the boundary.
- **Flap detection.** Nagios/Centreon track recent state-change frequency; an
  entity that changes state too often is flagged "flapping" and notifications
  are suppressed until it stabilises.

### 4.2 Alert *collection* (alert → incident)
- **Deduplication via fingerprint.** Alertmanager hashes `(rule name + label
  set)` into a fingerprint; an already-firing fingerprint does not produce a
  second notification. Squadcast/PagerDuty dedupe incoming alerts against
  open incidents for up to 48h.
- **Correlation / grouping.** Multiple alerts about the same host (or same
  cause) collapse into **one incident**. ServiceNow ITOM "Event Management"
  is built entirely around this: events → alerts → de-duplicated/correlated
  alert groups → a single incident task.
- **Incident lifecycle.** `open/triggered → acknowledged → resolved`, with an
  audit timeline of every state change and every alert that joined it.
- **Suppression / maintenance windows.** Planned-maintenance windows mute
  alerting so reboots don't page anyone.

### 4.3 What this means for us
We are building a **lightweight ITOM/RMM**, closest in shape to NinjaOne or
PRTG. We do **not** need ServiceNow's full CMDB-driven correlation. We need:
threshold rules with duration, severity tiers, hysteresis, dedup by
`(rule, agent, scope)`, and a simple incident that groups an agent's open
alerts. That is achievable on the current stack with two new tables and one
scheduled evaluator.

---

## 5. Recommended conceptual model

```
                 ┌─────────────┐
   metric rows → │ Alert Rule  │  threshold + duration + severity + hysteresis
                 └──────┬──────┘
                        │  evaluator (cron, every 30–60s)
                        ▼
                 ┌─────────────┐   stateful: firing / resolved
                 │   Alert     │   dedup key = (ruleId, agentId, scope)
                 └──────┬──────┘
                        │  correlation
                        ▼
                 ┌─────────────┐   groups all open alerts for an agent
                 │  Incident   │   open → acknowledged → resolved
                 └─────────────┘
```

- **Alert Rule** — a tenant-scoped definition. *"root disk usedPercent ≥ 90
  for 5 min = critical."* Ships with system defaults, editable per tenant.
- **Alert** — a stateful instance of a rule breach for one agent + scope
  (e.g. mountpoint `/`, interface `eth0`, GPU 0). It has `firing` and
  `resolved` states and a dedup key so re-evaluation updates rather than
  duplicates it.
- **Incident** — the human-facing record. **One open incident per (agent +
  metric category)** — e.g. a disk incident and a CPU incident on the same
  host are separate. Categories: `compute` (cpu/memory/load), `storage`
  (disk), `thermal` (gpu temp/sensors/fan), `power` (battery), `availability`
  (offline/flapping), `process`. Every new alert attaches to the matching
  open incident for its host. **Incidents close manually only** — even after
  all alerts recover, a human must resolve them (resolved alerts are shown so
  the operator can confirm before closing).

> **Decisions locked (2026-05-15):** incident scope = per (agent + metric
> category); notifications = in-portal only for v1 (channel abstraction
> designed but deferred); incident close = manual only.

---

## 6. Proposed threshold catalog (defaults)

Defaults below are starting points — all tenant-overridable. `for` =
duration the breach must persist. Recovery value = hysteresis clear point.

### 6.1 Core system
| Signal | Warning | Critical | `for` | Recover at | Notes |
|---|---|---|---|---|---|
| CPU `cpuPercent` | ≥ 85% | ≥ 95% | 5 min | < 75% | Sustained, not spikes |
| Memory `memoryPercent` | ≥ 85% | ≥ 95% | 5 min | < 80% | Pair with mem floor |
| Memory available `memAvailableBytes` | < 1 GB | < 512 MB | 5 min | > 1.5 GB | Absolute floor |
| Disk (root + per-volume) `usedPercent` | ≥ 80% | ≥ 90% | 10 min | < 78% | Per `mountpoint` |
| Load avg `loadAvg1m / cpuCores` | ≥ 1.5 | ≥ 3.0 | 10 min | < 1.0 | Normalise by cores |

### 6.2 Availability
| Signal | Severity | Condition |
|---|---|---|
| Agent offline | Critical | `agent_status_events` → `offline`, or `lastSeenAt` > 90s. No `for` window — the 90s staleness *is* the window. |
| Agent flapping | Warning | ≥ 4 online/offline transitions in 30 min → suppress per-transition alerts. |

### 6.3 Thermal & hardware
| Signal | Warning | Critical | `for` |
|---|---|---|---|
| GPU `temperatureC` | ≥ 85°C | ≥ 95°C | 3 min |
| Sensor `temperature_c` | ≥ 80°C | ≥ 90°C | 3 min |
| Sensor `fan_rpm` | — | = 0 while temp high | 2 min |
| GPU `utilizationPercent` | ≥ 95% | — | 15 min |

### 6.4 Battery
| Signal | Severity | Condition |
|---|---|---|
| Battery low | Warning | `percent` < 20% and `onAC` false |
| Battery critical | Critical | `percent` < 10% and `onAC` false |
| Battery health degraded | Warning | `healthPercent` < 70% |

### 6.5 Network (rate-derived)
| Signal | Warning | Notes |
|---|---|---|
| Interface throughput | ≥ 90% of link capacity | Needs link-speed; defer until we collect it. |
| Interface saturation (proxy) | sustained high `bytesRecv` delta | Ship later — counters need rate derivation first. |

### 6.6 Process
| Signal | Severity | Condition |
|---|---|---|
| Runaway process | Warning | single process `cpuPercent` ≥ 90% for 10 min |
| Process memory hog | Warning | single process `memoryBytes` > 50% of host RAM for 10 min |

---

## 7. Proposed data model

New NestJS module `backend/BE/src/alerts/` (mirrors how `discovery` is
structured). Entities use `synchronize: true` like the rest of the app, so
adding them to `app.module.ts` is enough.

### 7.1 `alert_rules`
| Column | Type | Purpose |
|---|---|---|
| `id` | uuid PK | |
| `tenantId` | string, null | null = global default rule |
| `name` | string | "Root disk almost full" |
| `metric` | enum | `cpu` / `memory` / `disk` / `load` / `gpu_temp` / `battery` / `agent_offline` / … |
| `scope` | enum | `host` / `mountpoint` / `interface` / `gpu` / `process` |
| `comparator` | enum | `gt` / `gte` / `lt` / `lte` / `eq` |
| `warningThreshold` | float, null | |
| `criticalThreshold` | float, null | |
| `recoveryThreshold` | float, null | hysteresis clear point |
| `forSeconds` | int | duration the breach must persist |
| `enabled` | bool | |
| `createdAt` / `updatedAt` | timestamptz | |

### 7.2 `alerts`
| Column | Type | Purpose |
|---|---|---|
| `id` | uuid PK | |
| `tenantId` | string | |
| `ruleId` | uuid FK | |
| `agentId` | string | |
| `scopeKey` | string | `/`, `eth0`, `gpu:0` — empty for host scope |
| `dedupKey` | string, unique-ish | `${ruleId}:${agentId}:${scopeKey}` |
| `severity` | enum | `warning` / `critical` |
| `state` | enum | `firing` / `resolved` |
| `metricValue` | float | value at last evaluation |
| `firstFiredAt` | timestamptz | |
| `lastEvaluatedAt` | timestamptz | |
| `resolvedAt` | timestamptz, null | |
| `incidentId` | uuid FK, null | |

Index `(tenantId, state)` and unique partial index on `dedupKey WHERE state='firing'`.

### 7.3 `incidents`
| Column | Type | Purpose |
|---|---|---|
| `id` | uuid PK | |
| `tenantId` | string | |
| `agentId` | string | the affected host |
| `category` | enum | `compute` / `storage` / `thermal` / `power` / `availability` / `process` |
| `title` | string | derived from highest-severity alert |
| `severity` | enum | max severity of attached alerts |
| `status` | enum | `open` / `acknowledged` / `resolved` (resolved set manually only) |
| `openedAt` / `acknowledgedAt` / `resolvedAt` | timestamptz | |
| `acknowledgedBy` | string, null | tenant user |
| `alertCount` | int | denormalised counter |

### 7.4 `incident_events` (audit timeline)
`id`, `incidentId`, `type` (`opened` / `alert_added` / `acknowledged` /
`resolved` / `comment`), `message`, `actor`, `occurredAt`.

---

## 8. Evaluation engine design

A NestJS `@Cron` job in `AlertsEvaluatorService`, running every **30–60s**
(aligned with the agent flush cadence — evaluating faster than data arrives
is wasted work).

**Per tick, per tenant:**
1. Load enabled rules (global defaults + tenant overrides; tenant wins on name collision).
2. For each rule, query the relevant metric table for each agent's recent
   window `[now − forSeconds, now]`.
3. **Breach test:** *every* sample in the window must violate the threshold
   (matches Google Cloud Monitoring's retest-window semantics — one good
   sample resets it). This is what makes `for` meaningful.
4. Determine severity: critical threshold beats warning.
5. **State transition** keyed by `dedupKey`:
   - No firing alert + breach sustained → **create** `firing` alert, attach
     to (or open) the agent's incident.
   - Firing alert + still breached → **update** `metricValue`, `lastEvaluatedAt`.
   - Firing alert + value crossed **recovery threshold** → mark `resolved`.
   - Firing alert + severity changed → update severity, log incident event.
6. **Agent-offline** rule is special — driven off `agent_status_events` /
   `lastSeenAt` rather than a metric window.
7. **Flap guard:** if an agent produced ≥ N transitions in the last 30 min,
   suppress new alerts for it and raise a single "flapping" warning instead.

**Incident correlation:** one open incident per `(agentId, category)`. A new
alert maps its rule's `metric` to a category, then attaches to the matching
open incident for the host or opens one. Incident `severity` = max of
attached firing alerts. **Incidents do not auto-resolve** — when all attached
alerts clear, the incident stays `open` with a "ready to close" hint; a human
acknowledges/resolves it. Enforce one-open-per-host-category with a unique
partial index on `(agentId, category) WHERE status != 'resolved'`.

**Network rate handling:** for counter metrics, the evaluator fetches the two
most recent samples per interface, computes `Δ/Δt`, discards negative deltas
(counter reset), and thresholds the rate.

---

## 9. API surface

`backend/BE/src/alerts/alerts.controller.ts` — all tenant-scoped via the
existing `TenantContextMiddleware`:

| Method | Route | Purpose |
|---|---|---|
| GET | `/v1/alerts` | list alerts, filter by `state`, `severity`, `agentId` |
| GET | `/v1/incidents` | list incidents, filter by `status` |
| GET | `/v1/incidents/:id` | incident detail + alerts + timeline |
| POST | `/v1/incidents/:id/acknowledge` | ack |
| POST | `/v1/incidents/:id/resolve` | manual resolve |
| POST | `/v1/incidents/:id/comment` | timeline note |
| GET | `/v1/alert-rules` | list rules (defaults + overrides) |
| POST/PATCH | `/v1/alert-rules` | create / edit a tenant rule |

The dashboard's existing "Latest incidents" card switches from the fake
offline-agent derivation to a real `GET /v1/incidents?status=open` call.

---

## 10. Portal UI plan

Reuse the established ITOM table pattern (`src/components/ui/table.tsx`) and
`severity-badge.tsx` / `status-badge.tsx`.

1. **`/incidents`** — incident list table: severity, title, agent, status,
   opened-at, alert count. Filters for status/severity.
2. **`/incidents/[id]`** — detail: header (severity, status, ack/resolve
   buttons), attached-alerts table, and a vertical **timeline** from
   `incident_events`.
3. **`/alerts`** — flat firing/resolved alert feed (optional; useful for
   debugging rules).
4. **`/settings` → Alert rules tab** — table of rules with inline threshold
   editing. Reset-to-default per rule.
5. **Dashboard** — wire `IncidentsCard` to the real endpoint; add an "open
   incidents by severity" KPI to `fleet-kpi-row.tsx`.

---

## 11. Phased implementation plan

| Phase | Scope | Exit criteria |
|---|---|---|
| **P1 — Data layer** | `alert_rules`, `alerts`, `incidents`, `incident_events` entities + module wired into `app.module.ts`; seed default rules. | Tables created; defaults seeded per tenant. |
| **P2 — Evaluator** | Cron evaluator for core metrics (CPU/mem/disk/load) with duration + hysteresis; alert state machine; agent-offline rule. | Filling a disk on a test agent fires a critical alert after the `for` window and resolves on recovery. |
| **P3 — Incidents** | Correlation, incident lifecycle, audit timeline, REST API. | Alerts group into an incident; ack/resolve works; timeline records every change. |
| **P4 — Portal UI** | `/incidents`, incident detail, real dashboard card. | Operator can see and act on incidents end-to-end. |
| **P5 — Rule config UI** | Settings tab to edit thresholds; flap guard; thermal/battery/GPU/process rules. | Tenant can tune thresholds; thermal & battery alerts live. |
| **P6 (later)** | Network-rate rules, notification channels (email/Slack), maintenance windows. | — |

---

## 12. Decisions & remaining open questions

**Decided (2026-05-15):**
- Incident granularity → **per (agent + metric category)**.
- Notifications → **in-portal only for v1**; design the channel abstraction, defer email/Slack.
- Incident close → **manual only**; incidents never auto-resolve.

**Still open:**
1. **Rule ownership** — ship a fixed set of system rules everyone gets, plus
   tenant overrides? Or let tenants create rules from scratch? Recommend
   defaults + overrides for v1.
2. **Evaluation cadence** — 30s vs 60s. 60s matches the agent flush; 30s
   gives faster detection at 2× query cost. Recommend 60s.
3. **Retention** — how long to keep resolved alerts / closed incidents?
   Suggest 30–90 days, then prune via the existing scheduler pattern.

---

## Sources

- [Behavior of metric-based alerting policies — Google Cloud Monitoring](https://docs.cloud.google.com/monitoring/alerts/concepts-indepth)
- [Reduce alert flapping — Datadog](https://docs.datadoghq.com/monitors/guide/reduce-alert-flapping/)
- [Introducing recovery thresholds for metric monitors — Datadog](https://www.datadoghq.com/blog/introducing-recovery-thresholds/)
- [Detection and Handling of State Flapping — Nagios Core](https://assets.nagios.com/downloads/nagioscore/docs/nagioscore/3/en/flapping.html)
- [How to Build Alert Deduplication Logic — OneUptime](https://oneuptime.com/blog/post/2026-01-30-alert-deduplication/view)
- [Monitoring and Alerting Best Practices to Reduce Alert Fatigue — OneUptime](https://oneuptime.com/blog/post/2026-02-20-monitoring-alerting-best-practices/view)
- [RMM: How to Tune Overlapping Monitoring Thresholds — NinjaOne](https://www.ninjaone.com/blog/how-to-tune-overlapping-monitoring-thresholds-in-rmm/)
- [Alert Deduplication Rules — SolarWinds/Squadcast](https://support.squadcast.com/services/alert-deduplication-rules/alert-deduplication-rules)
- [Alerting System Low-Level Design — TechInterview.org](https://www.techinterview.org/post/3233469424/lld-alerting-system/)
