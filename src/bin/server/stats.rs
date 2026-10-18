//! PHASE 7 — AGENT STATS · PART 2 (derived read-only projection).
//!
//! # Sources (authoritative, existing — NO new database)
//!
//! The stats projection reads the SAME two stores the leaderboard and
//! activity feed project, through the SAME authoritative readers:
//!
//!   * `artifact/agents/<uuid>.json` — via `agents::read_agent`;
//!   * `artifact/agent_payment_intents/<uuid>/<hex-key>.json` — via
//!     `agents::read_intent` / `agents::read_intent_v2` with the same
//!     v1/v2 document-tag routing every projection uses.
//!
//! # Hard read-only contract (same discipline as activity.rs /
//! leaderboard.rs)
//!
//! This module opens those stores for READING and nothing else. Render
//! paths are pure projections over parameterized directory roots. The
//! module contains NO `fs::create*` / `fs::write` / `fs::remove*` /
//! `fs::rename` / `fs::OpenOptions` calls anywhere in production code
//! (only the `#[cfg(test)]` fixtures mint temp-dir trees), NO
//! `crate::rialo` / `RialoConfig` / `PaymentOps` references, NO wallet
//! store access, and ZERO chain calls: rendering stats runs ZERO RPC.
//!
//! # Three lanes
//!
//!   * OWNER — `GET /api/agents/stats`: existing session
//!     (`crate::session_user`) + ownership filter; aggregates ALL of the
//!     caller's agents with owner-scoped recipient disclosure.
//!   * OWNER-PER-AGENT — `GET /api/agents/{id}/stats`: the same session
//!     auth, then the SAME `agents::load_authorized` choke point as every
//!     other agent route — missing, foreign, corrupt, and non-canonical
//!     all collapse to ONE indistinguishable `AGENT_NOT_FOUND`, plus a
//!     newest-50 confirmed timeline with recipients.
//!   * CREDENTIAL — `GET /api/agents/triggers/payments/stats`: the agent
//!     principal comes EXCLUSIVELY from exactly one `X-Agent-Credential`
//!     header (64 lowercase hex, Argon2-verified on disk) — every
//!     credential-layer failure is ONE `AGENT_CREDENTIAL_INVALID`; the
//!     timeline omits the recipient field entirely (the lane never
//!     reveals who the agent paid); no cross-agent data, no session.
//!
//! # Metric semantics (identical vocabulary to the leaderboard)
//!
//! The six-state buckets are computed by the SHARED `leaderboard::observe`
//! classifier (never re-derived here):
//!
//!   * confirmed_count        = `confirmed` + `reconciled_paid`
//!   * confirmed_volume_kelvin= sum of amount_kelvin over exactly those
//!     (integer `u64` `saturating_add`; no float money math)
//!   * confirmed_volume_rlo   = display-only kelvin / 1e9
//!   * failed_count           = `failed` + `reconciled_absent`
//!   * pending_count          = `pending`
//!   * unknown_count          = `unknown`
//!   * reconciled_count       = `reconciled_paid` + `reconciled_absent`
//!   * total_intent_count     = every slot parsed for the agent; the five
//!     buckets partition total by construction
//!   * first/last_confirmed_at= min/max `updated_at` over confirmed slots
//!   * confirmed_volume_by_day= per-UTC-day (`agents::utc_day(created_at)`)
//!     confirmed volume, days sorted DESC
//!
//! `unknown` / `pending` / `failed` / `reconciled_absent` NEVER
//! contribute to confirmed volume or the confirmed timeline.
//!
//! # Never rendered (DTO whitelist)
//!
//! Owner aggregate: `agents_total`, the `totals` block,
//! `confirmed_volume_by_day`, and the `agents` rows (the exact leaderboard
//! ordering: volume DESC, last_confirmed_at DESC null-last, confirmed
//! DESC, agent_id ASC — plus day-by-day + recipients per row).
//! Per-agent: `agent_id`, `name`, `status`, totals, day-by-day, timeline
//! (`at`, `amount_kelvin`, `amount_rlo`, `state`, `recipient` — the
//! credential lane drops `recipient`).
//!
//! NO private keys, NO credentials/PHC, NO idempotency keys, NO request
//! or policy fingerprints, NO reconciliation evidence, NO owner_user_id,
//! NO wallet paths, NO session tokens, NO failure internals, NO raw
//! response blobs. DTOs are built field by field; raw stored records are
//! never serialized into a response.
//!
//! # Fail-closed rules (identical to the other projections)
//!
//!   * agents directory missing     -> empty board (no agents yet);
//!   * any other agents read error  -> Store;
//!   * a `.json` agent file that fails `read_agent` -> Store
//!     (foreign-owner files are SKIPPED — not this caller's board);
//!   * an agent whose recorded id is not canonical -> Store;
//!   * an intents directory missing -> zero metrics (no ledger = no
//!     history);
//!   * non-`.json` / non-canonical-lowercase-hex file names -> inert;
//!   * an unknown `schema_version` document -> inert;
//!   * a slot that FAILS the authoritative reader (corrupt JSON,
//!     identity mismatch) -> Store: a corrupted ledger is NEVER quietly
//!     zeroed — a partial stats readout is a dangerous readout.
//!
//! # Determinism
//!
//!   * every directory listing is flattened and name-sorted before use;
//!   * per-agent rows use the exact leaderboard total order;
//!   * the timeline is newest-first: `updated_at` DESC, then
//!     (reconciled_paid before confirmed), then `created_at` DESC, then
//!     amount DESC, then lexicographic identity — a total, stable order
//!     bounded to the newest 50 confirmed slots.
//!
//! # Part boundaries
//!
//! **Part 2.1** — the read-only core: the deterministic directory scans,
//! the typed internal projections, and the fail-closed/inert rules shared
//! with the leaderboard + activity projections. The core is
//! directory-parameterized, so it is fully exercised from temp-dir tests.
//!
//! **Part 2.2** — the deterministic timeline (at DESC, identity ASC,
//! capped at 50 AFTER ordering) and the daily-bucket determinism, exercised
//! from the same temp-dir suite.
//!
//! **Part 2.3** — the OWNER + SINGLE-AGENT HTTP surface:
//!
//!   * `GET /api/agents/stats` — owner aggregate over ALL of the
//!     authenticated user's agents (session -> owner_totals -> by_day).
//!   * `GET /api/agents/{id}/stats` — single-agent readout (session ->
//!     `load_authorized` choke point -> render_agent_stats_in).
//!
//! **Part 2.5.1** — the CREDENTIAL-LANE HTTP surface (the auth + handler
//! core):
//!
//!   * `GET /api/agents/triggers/payments/stats` — the agent principal
//!     comes EXCLUSIVELY from exactly one `X-Agent-Credential` header; the
//!     agent id is NEVER accepted from path/query/body; every
//!     credential-layer failure is ONE `AGENT_CREDENTIAL_INVALID`; the
//!     response is the SAME per-agent DTO as the owner lane
//!     (`render_agent_stats_in`, the existing credential-safe
//!     `with_recipient = false` path — `scope: agent_credential`, no
//!     `recipient` field on any timeline entry).
//!
//! All three lanes read only
//! `artifact/agents/` and `artifact/agent_payment_intents/`; no mutation,
//! no RPC, no wallet access, no payment execution, no credential changes.
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::Path as FsPath;
use uuid::Uuid;

/// The number of newest confirmed slots the HTTP per-agent lane renders.
/// Applied by `final_timeline` (Part 2.2): sort first, then truncate.
const TIMELINE_MAX: usize = 50;

// Process-wide test-CWD serialization (the chdir-based suites flip the
// shared process CWD; ALL chdir windows serialize on this one static —
// the same reason the stats24 suite exists).
//
// PHASE 9 UNIFICATION: this is a std::sync::Mutex (was tokio::sync::Mutex)
// so that BOTH async suites and plain sync tests (the tasks payout battery)
// serialize against the SAME lock — process-wide CWD is one global, and two
// lock objects for it were a cross-suite race. Guard-holding-across-await
// audit: every `CWD_LOCK.lock()` site runs inside `#[tokio::test]`
// current-thread tests (no multi-thread flavor anywhere in this crate),
// holds the guard only for the duration of its own chdir-window future, and
// the guard being non-Send is therefore fine (single-threaded polling).
// No call site re-enters the lock while held. Poisoning is recovered with
// into_inner() (a failed chdir must never wedge the whole battery).
pub(crate) static CWD_LOCK: std::sync::LazyLock<std::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(()));

// ---------------------------------------------------------------------------
// Shared aggregation core (temp-dir-testable; production passes the
// canonical artifact roots from crate::agents)
// ---------------------------------------------------------------------------

/// The shared six-state classifier's target: the SAME struct the
/// leaderboard accumulates into, so the two projections can never drift.
type Metrics = crate::leaderboard::Metrics;

/// The read-only core's outcome. A corrupted store is a fatal,
/// unclassified failure — the render cores fail closed and a LATER part
/// maps this onto the typed `AGENT_STORE_ERROR` envelope; nothing about
/// the corruption is ever rendered as a partial readout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StatsErrorKind {
    /// A trusted record was corrupt, unreadable, or identity-mismatched
    /// (or the store itself could not be listed).
    Store,
}

impl StatsErrorKind {
    /// Map the core outcome onto the fatal error type the render cores
    /// return.
    pub(crate) fn into_error(self) -> StatsError {
        StatsError(self)
    }
}

/// The core's fatal error (one shape: a corrupted trusted store).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StatsError(StatsErrorKind);

/// A confirmed slot's derived facts — the timeline + day-bucket input.
/// (No `PartialEq`/`Eq`/`Clone` derives: the slot is compared by its
/// fields at the projection boundary, never by whole-struct equality.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfirmedSlot {
    /// updated_at (the confirmed/reconciled_paid settle moment) — rendered as `at`
    pub at: i64,
    pub amount_kelvin: u64,
    /// canonical lowercase state name ("confirmed" | "reconciled_paid")
    pub state: &'static str,
    pub recipient: String,
    /// the canonical identity of the intent slot (the decoded idempotency
    /// key, canonical lowercase hex) — the projection's `deterministic_identity`.
    /// Internal ONLY: the timeline order's tie-breaker (`updated_at DESC,
    /// deterministic identity ASC`); never rendered (the DTO whitelist of
    /// Part 4/5 drops it at the boundary).
    pub deterministic_identity: String,
    /// created_at — the day-bucket key for `confirmed_by_day` (via
    /// `agents::utc_day`); NOT part of the timeline DTO.
    pub created_at: i64,
}

/// Per-agent internal projection: the shared six-state metrics (same
/// `leaderboard::Metrics` struct the leaderboard accumulates into, via the
/// shared `leaderboard::observe` classifier — the two projections can
/// never drift), the derived confirmed window, the per-UTC-day confirmed
/// volume, and the unbounded confirmed timeline.
///
/// PRIVACY: every field is a whitelisted public fact. This struct carries
/// no private keys, no credentials/PHC, no idempotency KEYS as stored
/// records (only the decoded key bytes as an internal ordering tie-break),
/// no request/policy fingerprints, no raw response blobs, no wallet paths,
/// and no `owner_user_id`. (Deliberately no `PartialEq`/`Eq`/`Clone`: the
/// shared `Metrics` struct is accumulator-only — never compared or copied
/// whole; the projection is compared field by field at the boundary.)
#[derive(Debug, Default)]
pub(crate) struct AgentStats {
    pub metrics: Metrics,
    /// min `updated_at` over confirmed slots (None when none confirmed)
    pub first_confirmed_at: Option<i64>,
    /// per-UTC-day confirmed volume (`agents::utc_day` keys)
    pub confirmed_by_day: BTreeMap<String, u64>,
    /// every confirmed slot (unbounded; the newest-50 bound is applied by
    /// `final_timeline` at projection time)
    pub timeline: Vec<ConfirmedSlot>,
}

impl AgentStats {
    /// Fold one confirmed slot into the projection: the day bucket, the
    /// first/last confirmed window, and the timeline.
    pub(crate) fn note_confirmed(&mut self, slot: ConfirmedSlot) {
        let day = crate::agents::utc_day(slot.created_at);
        *self.confirmed_by_day.entry(day).or_insert(0) += slot.amount_kelvin;
        self.first_confirmed_at = Some(match self.first_confirmed_at {
            Some(f) => f.min(slot.at),
            None => slot.at,
        });
        self.timeline.push(slot);
    }
}

/// Scan ONE agent's intents directory into `stats` using the exact v1/v2
/// routing and fail-closed rules as activity.rs / leaderboard.rs
/// (deterministic listing, inert non-hex names, inert unknown schema,
/// fail-closed on authoritative-reader errors).
pub(crate) fn scan_agent_intents(
    intents_root: &FsPath,
    id: &Uuid,
    stats: &mut AgentStats,
) -> Result<(), StatsError> {
    use crate::agents::{agent_intents_dir, read_intent, read_intent_v2};
    let dir = agent_intents_dir(intents_root, id);
    let entries: Vec<std::fs::DirEntry> = match std::fs::read_dir(&dir) {
        Ok(iter) => iter.flatten().collect(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(StatsErrorKind::Store.into_error()),
    };
    let mut names: Vec<String> = Vec::new();
    for entry in &entries {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue; // inert: only <hex>.json is a slot
        }
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            names.push(stem.to_string());
        }
    }
    names.sort(); // deterministic listing regardless of filesystem order

    for stem in names {
        // canonical lowercase even-length hex only — the same inert rule as
        // activity.rs / leaderboard.rs
        if stem.is_empty()
            || stem.len() % 2 != 0
            || !stem
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            continue;
        }
        let Some(key) = hex_decode(&stem) else {
            continue;
        };
        // route v1/v2 by the document's own version tag BEFORE any typed
        // reader rejects an unknown version (foreign stays inert, corrupt
        // stays fatal)
        let bytes = match std::fs::read(dir.join(format!("{stem}.json"))) {
            Ok(b) => b,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(StatsErrorKind::Store.into_error()),
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            return Err(StatsErrorKind::Store.into_error()); // unparseable ledger file
        };
        let state = match value.get("schema_version").and_then(|v| v.as_u64()) {
            Some(1) => {
                let intent = match read_intent(intents_root, id, &key) {
                    Ok(Some(intent)) => intent,
                    Ok(None) => continue,
                    Err(_) => return Err(StatsErrorKind::Store.into_error()),
                };
                (
                    intent.state,
                    intent.amount_kelvin,
                    intent.created_at,
                    intent.updated_at,
                    intent.recipient,
                )
            }
            Some(2) => {
                let intent = match read_intent_v2(intents_root, id, &key) {
                    Ok(Some(intent)) => intent,
                    Ok(None) => continue,
                    Err(_) => return Err(StatsErrorKind::Store.into_error()),
                };
                // v2 ExecState mirrors the six-state vocabulary 1:1 — the
                // SAME shared mapping the leaderboard uses.
                (
                    crate::leaderboard::v2_to_canonical(intent.exec_state),
                    intent.amount_kelvin,
                    intent.created_at,
                    intent.updated_at,
                    intent.recipient,
                )
            }
            _ => continue, // foreign/unknown document: inert, never metrics
        };
        let (state, amount_kelvin, created_at, updated_at, recipient) = state;
        // the shared classifier owns the bucket math (never re-derived)
        crate::leaderboard::observe(&mut stats.metrics, state, amount_kelvin, updated_at);
        if matches!(
            state,
            crate::agents::IntentState::Confirmed | crate::agents::IntentState::ReconciledPaid
        ) {
            stats.note_confirmed(ConfirmedSlot {
                at: updated_at,
                created_at,
                amount_kelvin,
                state: if state == crate::agents::IntentState::Confirmed {
                    "confirmed"
                } else {
                    "reconciled_paid"
                },
                recipient,
                deterministic_identity: stem.clone(),
            });
        }
    }
    Ok(())
}

fn hex_decode(input: &str) -> Option<String> {
    if input.len() % 2 != 0 {
        return None;
    }
    let bytes: Vec<u8> = (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16))
        .collect::<Result<_, _>>()
        .ok()?;
    String::from_utf8(bytes).ok()
}

/// The timeline's deterministic total order: newest-first, breaking ties by
/// `deterministic_identity ASC`:
///
///   1. `at` (updated_at) DESC
///   2. `deterministic_identity` ASC (canonical lowercase hex — a total
///      order, because every slot's identity is distinct on disk)
///
/// This is a complete, stable order for a `note_confirmed`-fed timeline, so
/// no further (state / created_at / amount) tie-breaker is needed.
///
/// The `TIMELINE_MAX` (50) cap is applied **after** the deterministic
/// ordering: sort first, then truncate to the newest 50 — the ordering is
/// never derived from anything other than `at` and `deterministic_identity`.
pub(crate) fn final_timeline(stats: &AgentStats) -> Vec<ConfirmedSlot> {
    // note_confirmed only ever pushes confirmed/reconciled_paid slots, so the
    // ordering below is the single source of truth for the total order.
    let mut slots: Vec<&ConfirmedSlot> = stats.timeline.iter().collect();
    slots.sort_by(|a, b| {
        b.at.cmp(&a.at)
            .then_with(|| a.deterministic_identity.cmp(&b.deterministic_identity))
    });
    let mut out: Vec<ConfirmedSlot> = slots.into_iter().cloned().collect();
    out.truncate(TIMELINE_MAX); // the newest-50 bound, applied AFTER ordering
    out
}

/// Map the lifecycle enum to its canonical lowercase public name (the same
/// strings `serde(rename_all = "lowercase")` already emits across the API).
fn agent_status_name(status: crate::agents::AgentStatus) -> &'static str {
    use crate::agents::AgentStatus as S;
    match status {
        S::Draft => "draft",
        S::Active => "active",
        S::Paused => "paused",
        S::Disabled => "disabled",
        S::Deleted => "deleted",
    }
}

/// The core's deterministic per-agent ordering: the EXACT leaderboard
/// total order (confirmed volume DESC, last_confirmed_at DESC null-last,
/// confirmed count DESC, agent_id ASC). A pure function of the projection
/// — never re-derived at the render/DTO layer.
pub(crate) fn agent_order(
    a: &crate::agents::Agent,
    am: &AgentStats,
    b: &crate::agents::Agent,
    bm: &AgentStats,
) -> std::cmp::Ordering {
    bm.metrics
        .volume_kelvin
        .cmp(&am.metrics.volume_kelvin)
        .then_with(
            || match (am.metrics.last_confirmed_at, bm.metrics.last_confirmed_at) {
                (Some(x), Some(y)) => y.cmp(&x),
                (Some(_), None) => std::cmp::Ordering::Less, // b (null) last
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            },
        )
        .then_with(|| bm.metrics.confirmed.cmp(&am.metrics.confirmed))
        .then_with(|| a.agent_id.cmp(&b.agent_id))
}

// ---------------------------------------------------------------------------
// Owner aggregation primitives (pure fold over per-agent projections)
// ---------------------------------------------------------------------------
//
// These primitives own the CROSS-AGENT aggregation math the owner lane
// renders. They are pure `&[AgentStats] -> StatsTotals` folds, exercised
// directly from temp-free unit tests (no directories, no minting):
//
//   * totals across agents            (sum of the six-state counters)
//   * first / last confirmed          (min / max over the per-agent
//                                       confirmed windows)
//   * distinct confirmed recipients   (dedup across agents)
//   * merged daily buckets            (per-UTC-day confirmed volume,
//                                       days merged across agents)
//
// The confirmed volume sums use `saturating_add` at EVERY level (the
// per-agent `leaderboard::observe` already saturates; this fold saturates
// again), so a hostile or corrupt ledger that overflows a `u64` day/total
// volume can never wrap a public readout around a small value — it caps
// at `u64::MAX`. The fold never re-buckets and re-derives the six-state
// vocabulary; it trusts the per-agent classification `scan_agent_intents`
// already produced, so the two projections can never drift.

/// Merge per-agent proven volumes across agents, saturating at every add.
/// An empty input or a volume that would overflow `u64` caps at
/// `u64::MAX` (never wraps to a small value).
pub(crate) fn saturating_total(volumes: &[u64]) -> u64 {
    volumes.iter().fold(0u64, |acc, v| acc.saturating_add(*v))
}

/// The min per-agent `first_confirmed_at` (None when no agent confirmed).
pub(crate) fn aggregate_first_confirmed(stats: &[&AgentStats]) -> Option<i64> {
    stats.iter().filter_map(|s| s.first_confirmed_at).min()
}

/// The max per-agent `last_confirmed_at` (None when no agent confirmed).
pub(crate) fn aggregate_last_confirmed(stats: &[&AgentStats]) -> Option<i64> {
    stats
        .iter()
        .filter_map(|s| s.metrics.last_confirmed_at)
        .max()
}

/// Distinct confirmed recipients across agents (dedup; the owner lane
/// reveals COUNTS, never the addresses themselves).
pub(crate) fn distinct_confirmed_recipients(stats: &[&AgentStats]) -> BTreeSet<String> {
    let mut set: BTreeSet<String> = BTreeSet::new();
    for s in stats {
        for slot in &s.timeline {
            set.insert(slot.recipient.clone());
        }
    }
    set
}

/// Merged per-UTC-day confirmed volume across agents, saturating at every
/// add. Keys are the `agents::utc_day` strings (`YYYY-MM-DD`); the map is
/// a `BTreeMap`, so it arrives in day order (the DTO layer sorts it DESC).
pub(crate) fn merged_daily_buckets(stats: &[&AgentStats]) -> BTreeMap<String, u64> {
    let mut by_day: BTreeMap<String, u64> = BTreeMap::new();
    for s in stats {
        for (day, vol) in &s.confirmed_by_day {
            let entry = by_day.entry(day.clone()).or_insert(0);
            *entry = entry.saturating_add(*vol);
        }
    }
    by_day
}

/// The owner's AGGREGATE over ALL of the caller's agents — the single
/// saturating fold the owner render core reads. Totals (six-state counters
/// summed across agents, per-agent volumes merged with `saturating_add`),
/// the confirmed window (min first / max last `updated_at`), the distinct
/// confirmed recipient count, and the merged per-UTC-day confirmed volumes.
/// Pure data-in / value-out: no directory reads here, so it is fully
/// unit-testable against hand-built per-agent projections.
pub(crate) fn owner_totals(stats: &[&AgentStats]) -> crate::agents::StatsTotals {
    let mut total = 0u64;
    let mut confirmed = 0u64;
    let mut volume = 0u64;
    let mut pending = 0u64;
    let mut failed = 0u64;
    let mut unknown = 0u64;
    let mut reconciled = 0u64;
    for s in stats {
        total += s.metrics.total;
        confirmed += s.metrics.confirmed;
        volume = volume.saturating_add(s.metrics.volume_kelvin);
        pending += s.metrics.pending;
        failed += s.metrics.failed;
        unknown += s.metrics.unknown;
        reconciled += s.metrics.reconciled;
    }
    crate::agents::StatsTotals {
        total,
        confirmed,
        volume_kelvin: volume,
        pending,
        failed,
        unknown,
        reconciled,
        first_confirmed_at: aggregate_first_confirmed(stats),
        last_confirmed_at: aggregate_last_confirmed(stats),
        distinct_recipients_confirmed: distinct_confirmed_recipients(stats).len() as u64,
    }
}

// ---------------------------------------------------------------------------
// Render cores (fs::read only; directory-parameterized for temp-dir tests;
// production callers pass the canonical artifact roots)
// ---------------------------------------------------------------------------

/// Build the `totals` DTO field by field (no raw record serialization).
/// `with_distinct_rcpt` selects the owner aggregate (distinct recipient
/// count) vs the per-agent/per-credential rows (fixed 0 — the per-agent
/// recipient list is a separate explicit field).
fn totals_json(ts: crate::agents::StatsTotals, with_distinct_rcpt: bool) -> serde_json::Value {
    serde_json::json!({
        "total_intent_count": ts.total,
        "confirmed_count": ts.confirmed,
        "confirmed_volume_kelvin": ts.volume_kelvin,
        "confirmed_volume_rlo": ts.volume_kelvin as f64 / 1_000_000_000.0,
        "pending_count": ts.pending,
        "failed_count": ts.failed,
        "unknown_count": ts.unknown,
        "reconciled_count": ts.reconciled,
        "first_confirmed_at": ts.first_confirmed_at,
        "last_confirmed_at": ts.last_confirmed_at,
        "distinct_recipients_confirmed": if with_distinct_rcpt { ts.distinct_recipients_confirmed } else { 0u64 },
    })
}

/// `confirmed_volume_by_day`, days sorted DESC (string DESC == date DESC
/// for the zero-padded `YYYY-MM-DD` keys).
fn by_day_json(by_day: &BTreeMap<String, u64>) -> serde_json::Value {
    let items: Vec<serde_json::Value> = by_day
        .iter()
        .rev()
        .map(|(day, volume)| {
            serde_json::json!({
                "day": day,
                "confirmed_volume_kelvin": volume,
                "confirmed_volume_rlo": *volume as f64 / 1_000_000_000.0,
            })
        })
        .collect();
    serde_json::Value::Array(items)
}

fn timeline_json(stats: &AgentStats, with_recipient: bool) -> serde_json::Value {
    let items: Vec<serde_json::Value> = final_timeline(stats)
        .iter()
        .map(|s| {
            let mut item = serde_json::json!({
                "at": s.at,
                "amount_kelvin": s.amount_kelvin,
                "amount_rlo": s.amount_kelvin as f64 / 1_000_000_000.0,
                "state": s.state,
            });
            if with_recipient {
                item["recipient"] = serde_json::Value::String(s.recipient.clone());
            }
            item
        })
        .collect();
    serde_json::Value::Array(items)
}

/// Per-agent confirmed-recipient list (owner lane per-agent rows + the
/// per-agent lane): distinct, lexicographically sorted — a stable
/// whitelist, no counts, no order leakage.
fn agent_recipients_json(s: &AgentStats) -> serde_json::Value {
    let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for slot in &s.timeline {
        set.insert(slot.recipient.clone());
    }
    serde_json::Value::Array(set.into_iter().map(serde_json::Value::String).collect())
}

/// Owner lane: aggregate over ALL of the caller's agents, per-agent rows in
/// the EXACT leaderboard order (volume DESC, last DESC null-last,
/// confirmed DESC, agent_id ASC).
pub(crate) fn render_owner_stats_in(
    agents_dir_path: &FsPath,
    intents_root: &FsPath,
    user_id: u64,
) -> Result<(serde_json::Value, Vec<serde_json::Value>), StatsError> {
    fn read_owned_agents(
        dir: &FsPath,
        user_id: u64,
    ) -> Result<Vec<crate::agents::Agent>, StatsError> {
        use crate::agents::read_agent;
        let entries: Vec<std::fs::DirEntry> = match std::fs::read_dir(dir) {
            Ok(iter) => iter.flatten().collect(),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(StatsErrorKind::Store.into_error()),
        };
        let mut names: Vec<(String, std::path::PathBuf)> = Vec::new();
        for entry in &entries {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue; // inert: only <uuid>.json is an agent record
            }
            let file = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            names.push((file, path));
        }
        names.sort_by(|a, b| a.0.cmp(&b.0)); // deterministic processing order
        let mut agents: Vec<crate::agents::Agent> = Vec::new();
        for (_, path) in names {
            match read_agent(&path) {
                Ok(agent) if agent.owner_user_id != user_id => continue, // foreign owner
                Ok(agent) => agents.push(agent),
                Err(_) => return Err(StatsErrorKind::Store.into_error()),
            }
        }
        Ok(agents)
    }
    use crate::agents::parse_agent_id;

    let agents = match read_owned_agents(agents_dir_path, user_id) {
        Ok(agents) => agents,
        Err(outcome) => return Err(outcome),
    };

    let mut rows: Vec<(crate::agents::Agent, AgentStats)> = Vec::with_capacity(agents.len());
    for agent in agents {
        let Some(id) = parse_agent_id(&agent.agent_id) else {
            // an owned record whose id is not canonical is corruption:
            // fail closed, never a partial readout.
            return Err(StatsErrorKind::Store.into_error());
        };
        let mut stats = AgentStats::default();
        if let Err(outcome) = scan_agent_intents(intents_root, &id, &mut stats) {
            return Err(outcome);
        }
        rows.push((agent, stats));
    }

    // EXACT leaderboard order (shared core comparator, see `agent_order`).
    rows.sort_by(|(a, am), (b, bm)| agent_order(a, am, b, bm));

    // Owner aggregate = the shared, saturating, temp-free primitive (the
    // single source of truth for every cross-agent metric the owner render
    // core shows — never re-derived inline).
    let stats_refs: Vec<&AgentStats> = rows.iter().map(|(_, s)| s).collect();
    let totals = owner_totals(&stats_refs);
    let by_day = merged_daily_buckets(&stats_refs);

    Ok((
        serde_json::json!({
            "success": true,
            "scope": "owner",
            "agents_total": rows.len(),
            "totals": totals_json(totals, true),
            "confirmed_volume_by_day": by_day_json(&by_day),
            "agents": rows
                .iter()
                .map(|(agent, s)| {
                    serde_json::json!({
                        "agent_id": agent.agent_id,
                        "name": agent.name,
                        "status": agent_status_name(agent.status),
                        "totals": totals_json(
                            crate::agents::StatsTotals {
                                total: s.metrics.total,
                                confirmed: s.metrics.confirmed,
                                volume_kelvin: s.metrics.volume_kelvin,
                                pending: s.metrics.pending,
                                failed: s.metrics.failed,
                                unknown: s.metrics.unknown,
                                reconciled: s.metrics.reconciled,
                                first_confirmed_at: s.first_confirmed_at,
                                last_confirmed_at: s.metrics.last_confirmed_at,
                                distinct_recipients_confirmed: 0,
                            },
                            false,
                        ),
                        "confirmed_volume_by_day": by_day_json(&s.confirmed_by_day),
                        "recipients": agent_recipients_json(s),
                    })
                })
                .collect::<Vec<_>>(),
        }),
        Vec::new(),
    ))
}

/// One agent's full readout: identity + totals + day-by-day + timeline
/// (with or without the recipient field, per lane).
///
/// PHASE 7 — AGENT STATS · PART 2.5.2: the credential lane's PRIVACY
/// boundary. The existing projection is reused for the six-state metric
/// vocabulary, but the CREDENTIAL DTO is built explicitly field-by-field
/// from the whitelist below — and the rendered JSON runs a fail-closed
/// absence gate BEFORE it ever leaves the handler (`assert_forbidden_material`):
///
///   * the `recipients` array (the per-agent recipient list — even though
///     the timeline's own `recipient` field is already off in this lane,
///     the array was still rendered and would disclose exactly WHO the
///     agent paid);
///   * every internal marker value the projection legitimately carries for
///     ordering/identity (the decoded slot identity and the full slot
///     identity hex) — the gate is the STRONGEST enforcement this module
///     can make: the rendered bytes are scanned, not the intent.
///
/// The owner lane keeps its existing DTO shape (see `render_agent_stats_in`
/// call sites; the gate is credential-lane only).
pub(crate) fn render_agent_stats_in(
    intents_root: &FsPath,
    id: &Uuid,
    name: &str,
    status: crate::agents::AgentStatus,
    with_recipient: bool,
) -> Result<serde_json::Value, StatsError> {
    let mut stats = AgentStats::default();
    if let Err(outcome) = scan_agent_intents(intents_root, id, &mut stats) {
        return Err(outcome);
    }
    Ok(serde_json::json!({
        "success": true,
        "scope": if with_recipient { "agent" } else { "agent_credential" },
        "agent_id": id.to_string(),
        "name": name,
        "status": agent_status_name(status),
        "totals": totals_json(crate::agents::StatsTotals {
            total: stats.metrics.total,
            confirmed: stats.metrics.confirmed,
            volume_kelvin: stats.metrics.volume_kelvin,
            pending: stats.metrics.pending,
            failed: stats.metrics.failed,
            unknown: stats.metrics.unknown,
            reconciled: stats.metrics.reconciled,
            first_confirmed_at: stats.first_confirmed_at,
            last_confirmed_at: stats.metrics.last_confirmed_at,
            distinct_recipients_confirmed: 0,
        }, false),
        "confirmed_volume_by_day": by_day_json(&stats.confirmed_by_day),
        "recipients": agent_recipients_json(&stats),
        "timeline": timeline_json(&stats, with_recipient),
    }))
}

/// The credential-lane absence gate (Part 2.5.2). `rendered` is the
/// EXACT JSON body about to leave the handler; `value_literals` are the
/// marker values this request's trusted fixture tree actually carries
/// (slot identities, the wallet address, the keypair seed, ...) — every
/// one of them MUST be absent from the body, together with the full
/// `FORBIDDEN_MATERIAL` key-name set. A match anywhere (a key name, a
/// value, a hex identity) is a privacy bug, fail-closed, before the
/// response is returned.
///
/// WHY value-level probes too: the key-name ban catches DTO regressions
/// ("recipients" re-appears), but a store record can carry marker bytes
/// inside a LEGITIMATE-looking numeric field (an amount, a day key) —
/// the value probe is the only check that catches that class.
///
/// Returns Ok(()) on clean; Err(()) on the first violation. The caller
/// maps Err onto the standard 500 `AGENT_STORE_ERROR` envelope (the
/// same fail-closed shape a corrupt store gets — a privacy violation
/// that got through the DTO builders is NOT rendered with partial data).
pub(crate) fn assert_render_clean(rendered: &str, value_literals: &[&str]) -> Result<(), ()> {
    // The DTO KEY NAMES that must never appear in a 200 credential-lane
    // body (the forbidden FIELDS' own names — see the test module doc in
    // _stats252_tests.rs for why `secret` and some path/ASCII tokens are
    // value probes instead).
    const FORBIDDEN_KEY_NAMES: &[&str] = &[
        "recipient",
        "idempotency_key",
        "request_fingerprint",
        "policy_fingerprint",
        "response",
        "reconciliation",
        "tx_signature",
        "failure",
        "authz",
        "wallet_address",
        "owner_user_id",
    ];
    for key in FORBIDDEN_KEY_NAMES {
        if rendered.contains(key) {
            return Err(());
        }
    }
    // The documented store PATH prefixes — the on-disk layout must never
    // leak (the agent-wallet dir, the credential store dir, the agent
    // metadata dir, the intents root).
    const FORBIDDEN_PATHS: &[&str] = &[
        "artifact/agent_wallets",
        "artifact/agent_credentials",
        "artifact/agents",
        "artifact/agent_payment_intents",
        "agent_wallets",
    ];
    for path in FORBIDDEN_PATHS {
        if rendered.contains(path) {
            return Err(());
        }
    }
    // The value-level probes (request-specific marker literals).
    for lit in value_literals {
        if !lit.is_empty() && rendered.contains(lit) {
            return Err(());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// PHASE 7 — AGENT STATS · PART 2.3 — HTTP handlers (owner + single-agent)
//
// GET /api/agents/stats — owner aggregate over ALL of the authenticated
// user's agents. Session auth -> render_owner_stats_in (owner-scoped).
//
// GET /api/agents/{id}/stats — single-agent readout. Session auth ->
// load_authorized choke point (missing/foreign/corrupt -> ONE
// indistinguishable AGENT_NOT_FOUND) -> render_agent_stats_in.
//
// Both handlers are READ-ONLY: they open only artifact/agents/ and
// artifact/agent_payment_intents/ for reading (via the authoritative
// readers); no mutation, no RPC, no wallet access, no payment execution.
// The expensive directory scan runs off the async executor (spawn_blocking),
// matching the credential-lane pattern in activity.rs.
// ---------------------------------------------------------------------------

/// GET /api/agents/stats — owner aggregate over ALL of the authenticated
/// user's agents.
pub async fn owner_stats(State(state): State<crate::AppState>, headers: HeaderMap) -> Response {
    let Some(user) = crate::session_user(&state, &headers) else {
        return crate::api_error(
            StatusCode::UNAUTHORIZED,
            "NOT_AUTHENTICATED",
            "Not logged in",
        );
    };
    let user_id = user.id;
    let agents_dir = crate::agents::agents_dir();
    let intents_root = crate::agents::intents_root();
    let outcome = tokio::task::spawn_blocking(move || {
        render_owner_stats_in(&agents_dir, &intents_root, user_id)
    })
    .await;
    match outcome {
        Ok(Ok(aggregate)) => Json(aggregate.0).into_response(),
        Ok(Err(_)) => crate::api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "AGENT_STORE_ERROR",
            "Agent stats store is unavailable",
        ),
        Err(join_err) => crate::api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "AGENT_STORE_ERROR",
            &format!("Agent stats scan failed: {join_err}"),
        ),
    }
}

/// GET /api/agents/{id}/stats — single-agent readout for the authenticated
/// owner. The authorization order is the established one: session ->
/// ownership choke point (missing/foreign/corrupt collapse to ONE
/// indistinguishable AGENT_NOT_FOUND) -> read-only projection.
pub async fn agent_stats(
    State(state): State<crate::AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(user) = crate::session_user(&state, &headers) else {
        return crate::api_error(
            StatusCode::UNAUTHORIZED,
            "NOT_AUTHENTICATED",
            "Not logged in",
        );
    };
    let agent = match crate::agents::load_authorized(&id, user.id) {
        Ok(agent) => agent,
        Err(resp) => return resp,
    };
    let Some(uuid) = crate::agents::parse_agent_id(&agent.agent_id) else {
        // an owned record whose id is not canonical is corruption:
        // collapse into the same indistinguishable AGENT_NOT_FOUND
        return crate::api_error(StatusCode::NOT_FOUND, "AGENT_NOT_FOUND", "Agent not found");
    };
    let intents_root = crate::agents::intents_root();
    let status = agent.status;
    let outcome = tokio::task::spawn_blocking(move || {
        render_agent_stats_in(&intents_root, &uuid, &agent.name, status, true)
    })
    .await;
    match outcome {
        Ok(Ok(json)) => Json(json).into_response(),
        Ok(Err(_)) => crate::api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "AGENT_STORE_ERROR",
            "Agent stats store is unavailable",
        ),
        Err(join_err) => crate::api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "AGENT_STORE_ERROR",
            &format!("Agent stats scan failed: {join_err}"),
        ),
    }
}

/// GET /api/agents/triggers/payments/stats — credential lane, the auth +
/// handler core (Part 2.5.1), PRIVACY-HARDENED (Part 2.5.2).
///
/// AUTH: the agent principal comes EXCLUSIVELY from exactly one
/// `X-Agent-Credential` header (64 lowercase hex, Argon2-verified against
/// the disk store off the async executor). The agent id is NEVER accepted
/// from path/query/body — the literal route wins matching, the handler
/// takes no Body, and the id used downstream is the one the credential
/// itself resolves. Every credential-layer failure collapses to ONE
/// stable 401 `AGENT_CREDENTIAL_INVALID`.
///
/// LIFECYCLE (Part 2.5.2): a credential that authenticates but whose
/// agent record no longer exists (the file was deleted) is a DIFFERENT
/// lifecycle error — 404 `AGENT_NOT_FOUND`. The two are ordered: the
/// credential layer runs FIRST (missing agent + bad credential is 401),
/// the existence gate is SECOND.
///
/// PRIVACY (Part 2.5.2): the response is the SAME per-agent DTO as the
/// owner lane for the metric vocabulary (the existing projection is
/// reused, `with_recipient = false` — no `recipient` on any timeline
/// entry), but the CREDENTIAL body is built explicitly field-by-field
/// from a whitelist and the `recipients` array is REMOVED (the
/// per-agent recipient list discloses WHO the agent paid). The rendered
/// JSON then runs `assert_render_clean` BEFORE it leaves the handler:
/// key-name + path + value probes fail closed onto the standard 500
/// `AGENT_STORE_ERROR` envelope, so a privacy violation can never leave
/// with partial data. The credential plaintext is dropped at the end of
/// resolution and never logged, echoed, or rendered.
pub async fn agent_trigger_stats(headers: HeaderMap) -> Response {
    fn credential_invalid() -> Response {
        crate::api_error(
            StatusCode::UNAUTHORIZED,
            "AGENT_CREDENTIAL_INVALID",
            "A valid X-Agent-Credential header is required to resolve the agent principal",
        )
    }
    fn agent_not_found() -> Response {
        crate::api_error(StatusCode::NOT_FOUND, "AGENT_NOT_FOUND", "Agent not found")
    }
    fn store_error() -> Response {
        crate::api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "AGENT_STORE_ERROR",
            "Agent stats store is unavailable",
        )
    }
    let mut cred_values = headers.get_all("x-agent-credential").iter();
    let credential = match (cred_values.next(), cred_values.next()) {
        (Some(value), None) => value
            .to_str()
            .ok()
            .filter(|c| crate::agents::valid_credential_shape(c))
            .map(|c| c.to_string()),
        _ => None,
    };
    let Some(credential) = credential else {
        return credential_invalid();
    };
    // The credential layer runs FIRST and collapses to 401 before any
    // store access — an invalid credential is never masked by store
    // state (the same order the trigger activity lane uses).
    let auth = {
        let credential = credential.clone();
        tokio::task::spawn_blocking(move || {
            let uuid = crate::agent_credentials::authenticate_agent_credential(&credential)
                .map_err(|_| ())?;
            drop(credential);
            Ok::<_, ()>(uuid)
        })
        .await
    };
    let Ok(Ok(uuid)) = auth else {
        return credential_invalid();
    };
    let credential_presented = credential; // kept for the render gate's value probe
    let outcome = tokio::task::spawn_blocking(move || {
        use std::path::PathBuf;
        // the credential-resolved principal's record: its ABSENCE is the
        // lifecycle error the spec maps onto 404 (a credential that
        // verifies against an agent that no longer exists), its CORRUPTION
        // is a store error (500), and its canonical identity fields are the
        // body's display data (agent id, name, status — the same fields
        // the owner lane renders).
        let agents = crate::agents::agents_dir();
        let agent_path: PathBuf = crate::agents::agent_path(&agents, &uuid);
        // 404-vs-500 split: a MISSING record is `AGENT_NOT_FOUND`; a
        // PRESENT-but-unparseable record (or a schema-version mismatch)
        // is `AGENT_STORE_ERROR` — the same corruption the owner lane
        // fails closed on.
        let agent_bytes = match std::fs::read(&agent_path) {
            Ok(bytes) => bytes,
            Err(err) if matches!(err.kind(), std::io::ErrorKind::NotFound) => {
                return Ok(Err(agent_not_found()));
            }
            Err(_) => return Ok(Err(store_error())),
        };
        let agent: crate::agents::Agent =
            match serde_json::from_slice::<crate::agents::Agent>(&agent_bytes) {
                // the SAME validation `read_agent` applies (same schema const):
                // a parse or schema failure is store corruption -> 500.
                Ok(a) if a.schema_version == crate::agents::AGENT_SCHEMA_VERSION => a,
                _ => return Ok(Err(store_error())),
            };
        // the record's stored id must match the credential-resolved uuid
        // (a record that disagrees with its own filename is corruption)
        if crate::agents::parse_agent_id(&agent.agent_id).is_none()
            || agent.agent_id != uuid.to_string()
        {
            return Ok(Err(store_error()));
        }
        // ---- Part 2.5.2: CREDENTIAL-LANE AGENTS-STORE INTEGRITY GATE ----
        // The credential lane can never serve a PARTIAL board: EVERY
        // agent record on disk is parsed with the SAME authoritative
        // reader the owner lane uses (`agents::read_agent`). Any
        // corruption anywhere in the agent-METADATA store fails closed
        // to 500 AGENT_STORE_ERROR — a silent skip here would render a
        // stats readout out of a damaged store (the owner lane never
        // skips and never fails on FOREIGN files, so it is unchanged).
        let entries = match std::fs::read_dir(&agents) {
            Ok(iter) => iter.flatten().collect::<Vec<_>>(),
            Err(_) => return Ok(Err(store_error())),
        };
        let mut agent_files: Vec<std::path::PathBuf> = Vec::new();
        for entry in &entries {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue; // inert: only <uuid>.json is an agent record
            }
            agent_files.push(path);
        }
        agent_files.sort(); // deterministic enumeration order
        for path in &agent_files {
            if crate::agents::read_agent(path).is_err() {
                return Ok(Err(store_error()));
            }
        }
        let intents_root = crate::agents::intents_root();
        // The shared projection core (the owner-lane per-agent DTO,
        // `with_recipient = false` — no timeline `recipient` fields) is
        // rendered ONCE; the credential body below copies its field
        // VALUES through the explicit whitelist and nothing else.
        let view = render_agent_stats_in(&intents_root, &uuid, &agent.name, agent.status, false)
            .map_err(|_| store_error())?;
        // ---- Part 2.5.2 privacy rendering --------------------------------
        // Explicit credential-safe whitelist: the CREDENTIAL body takes
        // EXACTLY these eight top-level fields and nothing else — the
        // projection's `recipients` array is not in the whitelist, no
        // timeline entry carries `recipient` (the projection was
        // rendered `with_recipient = false`), and
        // `totals.distinct_recipients_confirmed` is DELETED after the
        // copy (its key contains the substring "recipient" and is a
        // count the credential lane never discloses). The wallet
        // address, owner_user_id, credential material, fingerprints,
        // response/reconciliation internals, and store paths are
        // structurally absent — and the rendered body still runs the
        // value-level probe gate below before it leaves the handler.
        let mut body = serde_json::json!({
            "success": true,
            "scope": "agent_credential",
            "agent_id": uuid.to_string(),
            "name": agent.name,
            "status": view.get("status").cloned().unwrap_or(serde_json::Value::Null),
            "totals": view.get("totals").cloned().unwrap_or(serde_json::Value::Null),
            "confirmed_volume_by_day": view
                .get("confirmed_volume_by_day")
                .cloned()
                .unwrap_or(serde_json::Value::Array(Vec::new())),
            "timeline": view
                .get("timeline")
                .cloned()
                .unwrap_or(serde_json::Value::Array(Vec::new())),
        });
        if let Some(obj) = body.get_mut("totals").and_then(|t| t.as_object_mut()) {
            obj.remove("distinct_recipients_confirmed");
        }
        let rendered = serde_json::to_string(&body).map_err(|_| store_error())?;
        // The value-level probes: the values this request's trusted store
        // ACTUALLY carries. Slot-identity hex (the on-disk slot filenames,
        // i.e. the idempotency key values), the agent's wallet address
        // (the fixture's WALLET_MARKER), and the credential plaintext
        // itself (presented in the header, never echoed in the body).
        // The key-name + path probes inside `assert_render_clean` cover
        // the rest of the matrix.
        let mut value_literals: Vec<String> = Vec::new();
        value_literals.push(hex_identity_of_intents(&intents_root, &uuid));
        if let Some(w) = &agent.wallet_address {
            value_literals.push(w.clone());
        }
        value_literals.push(credential_presented.clone());
        let literals: Vec<&str> = value_literals.iter().map(|s| s.as_str()).collect();
        if let Err(()) = assert_render_clean(&rendered, &literals) {
            // a privacy probe fired: fail closed, NO partial body, the
            // standard store-error envelope (indistinguishable)
            return Ok(Err(store_error()));
        }
        Ok::<_, Response>(Ok(rendered))
    })
    .await;
    match outcome {
        Ok(Ok(Ok(rendered))) => (StatusCode::OK, rendered).into_response(),
        Ok(Ok(Err(resp))) => resp,
        Ok(Err(_)) => store_error(),
        Err(_) => store_error(),
    }
}

/// The credential-resolved agent's slot-identity hex (the on-disk
/// filenames under the agent's intents dir) — the value-level probe for
/// idempotency key materials. Returns "" when there is nothing to probe
/// (an empty/missing intents dir is a valid readout, not a probe input).
fn hex_identity_of_intents(intents_root: &FsPath, id: &Uuid) -> String {
    let dir = crate::agents::agent_intents_dir(intents_root, id);
    let Ok(iter) = std::fs::read_dir(&dir) else {
        return String::new();
    };
    let mut names: Vec<String> = Vec::new();
    for entry in iter.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            names.push(stem.to_string());
        }
    }
    names.sort();
    names.join(",")
}

// ---------------------------------------------------------------------------
// PHASE 7 — AGENT STATS · PART 2.1 — focused temp-dir tests
//
// Drives the read-only CORES (`scan_agent_intents`, `render_owner_stats_in`,
// `render_agent_stats_in`, `final_timeline`) against minted temp-dir
// fixtures ONLY. No production artifact path is ever opened here; the
// directory parameters are the whole point of the core's shape.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests21 {
    use super::*;
    use crate::agents::AgentStatus;
    use std::path::{Path, PathBuf};
    use std::str::FromStr;
    use uuid::Uuid;
    const AGENT_A: &str = "11111111-1111-4111-8111-111111111111";
    const AGENT_B: &str = "22222222-2222-4222-8222-222222222222";

    /// A temp root with auto-drop on failure/success alike.
    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "rialo-stats21-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
        fn join(&self, p: &std::path::Path) -> PathBuf {
            self.0.join(p)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Whole-tree snapshot: byte-identical before/after the scan, plus a
    /// check that NO new entries (temp files, dirs, debris) appeared.
    fn snapshot(
        root: &PathBuf,
    ) -> (
        std::collections::BTreeMap<PathBuf, u64>,
        Vec<std::path::PathBuf>,
    ) {
        let mut files = std::collections::BTreeMap::new();
        let mut entries = walk(root);
        for entry in &entries {
            files.insert(entry.clone(), file_hash(entry));
        }
        (files, entries)
    }

    fn walk(root: &std::path::Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            if let Ok(read) = std::fs::read_dir(&dir) {
                for entry in read.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        stack.push(path);
                    } else {
                        out.push(path);
                    }
                }
            }
        }
        out.sort();
        out
    }

    fn file_hash(path: &std::path::Path) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        std::fs::read(path).unwrap().hash(&mut h);
        path.hash(&mut h);
        h.finish()
    }

    /// Write raw bytes under the temp root (test-side writing only; the
    /// production core never writes).
    fn put(root: &TempRoot, rel: &str, contents: &str) {
        let path = root.join(std::path::Path::new(rel));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, contents).unwrap();
    }

    /// One valid agent record (schema v1, canonical id, fixed owner/status).
    fn agent_record(id: &str, owner: u64, status: &str) -> String {
        format!(
            r#"{{"schema_version":1,"agent_id":"{id}","owner_user_id":{owner},"name":"Agent {id}","status":"{status}","wallet_address":null,"created_at":1000000000,"updated_at":1000000000}}"#
        )
    }

    fn put_agent(root: &TempRoot, agents_dir: &str, id: &str, owner: u64, status: &str) {
        put(
            root,
            &format!("{agents_dir}/{id}.json"),
            &agent_record(id, owner, status),
        );
    }

    /// One valid v1 intent (schema 1) with the reader-required identity.
    fn v1_intent(
        id: &str,
        key: &str,
        state: &str,
        amount: u64,
        created_at: i64,
        updated_at: i64,
        recipient: &str,
    ) -> String {
        format!(
            r#"{{"schema_version":1,"agent_id":"{id}","idempotency_key":"{key}","request_fingerprint":"{fingerprint}","recipient":"{recipient}","amount_kelvin":{amount},"state":"{state}","response":null,"created_at":{created_at},"updated_at":{updated_at},"reconciliation":null}}"#,
            fingerprint = "0000000000000000"
        )
    }

    /// One valid v2 intent (schema 2) — mirrors the v2 wire shape the
    /// authoritative reader accepts (exec_state + principal_kind agent).
    fn v2_intent(
        id: &str,
        key: &str,
        exec_state: &str,
        amount: u64,
        created_at: i64,
        updated_at: i64,
        recipient: &str,
    ) -> String {
        format!(
            r#"{{"schema_version":2,"agent_id":"{id}","intent_id":"{id}0000-0000-4000-8000-000000000000","idempotency_key":"{key}","request_fingerprint":"{fingerprint}","principal_kind":"agent","recipient":"{recipient}","amount_kelvin":{amount},"authz":{{"policy_fingerprint":"{fingerprint}","authorized_at":{created_at}}},"exec_state":"{exec_state}","tx_signature":null,"failure":null,"response":null,"reconciliation":null,"created_at":{created_at},"updated_at":{updated_at}}}"#,
            fingerprint = "0000000000000000"
        )
    }

    fn hex_key(input: &str) -> String {
        let mut out = String::new();
        for b in input.as_bytes() {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }

    fn put_intent(root: &TempRoot, intents: &str, id: &str, key: &str, doc: &str) {
        put(
            root,
            &format!("{intents}/{id}/{hex}.json", hex = hex_key(key)),
            doc,
        );
    }

    fn a() -> Uuid {
        Uuid::parse_str(AGENT_A).unwrap()
    }
    fn b() -> Uuid {
        Uuid::parse_str(AGENT_B).unwrap()
    }

    // ---- empty / missing directories ------------------------------------

    #[test]
    fn missing_directories_yield_empty_projections_not_errors() {
        let root = TempRoot::new();
        let (agents_dir, intents) = ("agents-nosuch", "intents-nosuch");
        // owner lane: no agents dir at all -> empty board, zero agents
        let (aggregate, rows) = render_owner_stats_in(
            &root.join(Path::new(agents_dir)),
            &root.join(Path::new(intents)),
            42,
        )
        .expect("missing dirs must not fail the core");
        assert!(rows.is_empty());
        assert_eq!(aggregate["agents_total"], 0);
        assert_eq!(
            aggregate["agents"].as_array().unwrap().len(),
            0,
            "no per-agent rows on an empty board"
        );
        assert_eq!(aggregate["totals"]["confirmed_count"], 0);
        assert_eq!(aggregate["totals"]["confirmed_volume_kelvin"], 0);
        assert_eq!(
            aggregate["confirmed_volume_by_day"]
                .as_array()
                .unwrap()
                .len(),
            0
        );

        // per-agent lane: missing intents dir -> zero metrics, no error
        let view = render_agent_stats_in(
            &root.join(Path::new(intents)),
            &a(),
            "a",
            AgentStatus::Active,
            true,
        )
        .expect("missing intents dir must not fail the core");
        assert_eq!(view["totals"]["total_intent_count"], 0);
        assert_eq!(view["timeline"].as_array().unwrap().len(), 0);
        assert!(view["totals"]["last_confirmed_at"].is_null());
    }

    #[test]
    fn empty_directories_yield_empty_projections_not_errors() {
        let root = TempRoot::new();
        std::fs::create_dir_all(root.join(Path::new("agents-empty"))).unwrap();
        std::fs::create_dir_all(root.join(Path::new("intents-empty"))).unwrap();
        let (aggregate, rows) = render_owner_stats_in(
            &root.join(Path::new("agents-empty")),
            &root.join(Path::new("intents-empty")),
            42,
        )
        .unwrap();
        assert!(rows.is_empty());
        assert_eq!(aggregate["agents_total"], 0);

        let mut stats = AgentStats::default();
        scan_agent_intents(&root.join(Path::new("intents-empty")), &a(), &mut stats).unwrap();
        assert_eq!(stats.metrics.total, 0);
        assert!(stats.timeline.is_empty());
    }

    // ---- valid v1 -------------------------------------------------------

    #[test]
    fn valid_v1_confirmed_lands_in_metrics_timeline_and_day_bucket() {
        let root = TempRoot::new();
        let (agents_dir, intents) = ("agents-v1", "intents-v1");
        put_agent(&root, agents_dir, AGENT_A, 42, "active");
        put_intent(
            &root,
            intents,
            AGENT_A,
            "key-1",
            &v1_intent(
                AGENT_A,
                "key-1",
                "confirmed",
                1_500_000_000,
                1_700_000_000,
                1_700_000_100,
                "rlo:recipient-a",
            ),
        );
        put_agent(&root, agents_dir, AGENT_B, 42, "draft");
        put_intent(
            &root,
            intents,
            AGENT_B,
            "key-1",
            &v1_intent(
                AGENT_B,
                "key-1",
                "pending",
                999,
                1_700_000_200,
                1_700_000_300,
                "rlo:recipient-b",
            ),
        );

        let mut stats = AgentStats::default();
        scan_agent_intents(&root.join(Path::new(intents)), &a(), &mut stats).unwrap();
        assert_eq!(stats.metrics.total, 1);
        assert_eq!(stats.metrics.confirmed, 1);
        assert_eq!(stats.metrics.volume_kelvin, 1_500_000_000);
        assert_eq!(stats.metrics.pending, 0);
        assert_eq!(stats.metrics.failed, 0);
        assert_eq!(stats.metrics.unknown, 0);
        assert_eq!(stats.metrics.reconciled, 0);
        assert_eq!(stats.first_confirmed_at, Some(1_700_000_100));
        assert_eq!(stats.metrics.last_confirmed_at, Some(1_700_000_100));
        assert_eq!(
            stats.timeline.len(),
            1,
            "exactly one confirmed slot in the timeline"
        );
        assert_eq!(stats.timeline[0].recipient, "rlo:recipient-a");
        // day bucket keyed by the UTC day of created_at via agents::utc_day
        let day = crate::agents::utc_day(1_700_000_000);
        assert_eq!(*stats.confirmed_by_day.get(&day).unwrap(), 1_500_000_000);

        // owner-lane aggregate over both agents: EXACT leaderboard order
        let (aggregate, rows) = render_owner_stats_in(
            &root.join(Path::new(agents_dir)),
            &root.join(Path::new(intents)),
            42,
        )
        .unwrap();
        assert!(rows.is_empty());
        assert_eq!(aggregate["agents_total"], 2);
        let agents = aggregate["agents"].as_array().unwrap();
        assert_eq!(agents.len(), 2, "exactly two per-agent rows");
        assert_eq!(agents[0]["agent_id"], AGENT_A); // volume 1.5e9 first
        assert_eq!(agents[1]["agent_id"], AGENT_B); // pending only
        assert_eq!(aggregate["totals"]["total_intent_count"], 2);
        assert_eq!(
            aggregate["totals"]["confirmed_volume_kelvin"],
            1_500_000_000
        );
        assert_eq!(aggregate["totals"]["distinct_recipients_confirmed"], 1);

        // per-agent lane: timeline + recipients
        let view = render_agent_stats_in(
            &root.join(Path::new(intents)),
            &a(),
            "a",
            AgentStatus::Active,
            true,
        )
        .unwrap();
        let timeline = view["timeline"].as_array().unwrap();
        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline[0]["state"], "confirmed");
        assert_eq!(timeline[0]["amount_kelvin"], 1_500_000_000);
        assert_eq!(timeline[0]["amount_rlo"], 1.5);
        assert_eq!(timeline[0]["recipient"], "rlo:recipient-a");
        assert!(view["recipients"].is_array());
    }

    #[test]
    fn valid_v1_reconciled_pages_via_shared_classifier() {
        let root = TempRoot::new();
        let (agents_dir, intents) = ("agents-v1r", "intents-v1r");
        put_agent(&root, agents_dir, AGENT_A, 42, "active");
        // six v1 states: the shared classifier must bucket each exactly once
        for (i, state) in [
            "pending",
            "confirmed",
            "failed",
            "unknown",
            "reconciled_paid",
            "reconciled_absent",
        ]
        .iter()
        .enumerate()
        {
            let key = format!("state-{i}");
            put_intent(
                &root,
                intents,
                AGENT_A,
                &key,
                &v1_intent(
                    AGENT_A,
                    &key,
                    state,
                    1_000_000_000,
                    1_700_000_000 + i as i64,
                    1_701_000_000 + i as i64,
                    "rlo:x",
                ),
            );
        }
        let mut stats = AgentStats::default();
        scan_agent_intents(&root.join(Path::new(intents)), &a(), &mut stats).unwrap();
        assert_eq!(stats.metrics.total, 6);
        assert_eq!(stats.metrics.pending, 1);
        assert_eq!(stats.metrics.confirmed, 2); // confirmed + reconciled_paid
        assert_eq!(stats.metrics.volume_kelvin, 2_000_000_000);
        assert_eq!(stats.metrics.failed, 2); // failed + reconciled_absent
        assert_eq!(stats.metrics.unknown, 1);
        assert_eq!(stats.metrics.reconciled, 2);
        // confirmed timeline = exactly the two confirmed slots
        assert_eq!(
            stats.timeline.len(),
            2,
            "exactly the confirmed + reconciled_paid slots"
        );
        assert_eq!(
            stats.first_confirmed_at,
            Some(1_701_000_001), // confirmed(updated 1_701_000_001)
        );
        assert_eq!(
            stats.metrics.last_confirmed_at,
            Some(1_701_000_004), // reconciled_paid(updated 1_701_000_004)
        );
        // owner-lane aggregate: the single agent's row is present, in order
        let (aggregate, rows) = render_owner_stats_in(
            &root.join(Path::new(agents_dir)),
            &root.join(Path::new(intents)),
            42,
        )
        .unwrap();
        assert!(rows.is_empty());
        assert_eq!(aggregate["agents_total"], 1);
        let agents = aggregate["agents"].as_array().unwrap();
        assert_eq!(agents.len(), 1, "exactly one per-agent row");
        assert_eq!(agents[0]["agent_id"], AGENT_A);
    }

    // ---- valid v2 -------------------------------------------------------

    #[test]
    fn valid_v2_confirmed_maps_through_v2_to_canonical() {
        let root = TempRoot::new();
        let (agents_dir, intents) = ("agents-v2", "intents-v2");
        put_agent(&root, agents_dir, AGENT_A, 42, "active");
        put_intent(
            &root,
            intents,
            AGENT_A,
            "v2-key-1",
            &v2_intent(
                AGENT_A,
                "v2-key-1",
                "confirmed",
                700_000_000,
                1_702_000_000,
                1_702_000_100,
                "rlo:recipient-v2",
            ),
        );
        // owner-lane aggregate must also carry the v2-derived volume
        let (aggregate, rows) = render_owner_stats_in(
            &root.join(Path::new(agents_dir)),
            &root.join(Path::new(intents)),
            42,
        )
        .unwrap();
        assert!(rows.is_empty());
        assert_eq!(aggregate["totals"]["confirmed_volume_kelvin"], 700_000_000);
        let mut stats = AgentStats::default();
        scan_agent_intents(&root.join(Path::new(intents)), &a(), &mut stats).unwrap();
        assert_eq!(stats.metrics.total, 1);
        assert_eq!(stats.metrics.confirmed, 1);
        assert_eq!(stats.metrics.volume_kelvin, 700_000_000);
        assert_eq!(stats.timeline[0].state, "confirmed");
        assert_eq!(stats.timeline[0].recipient, "rlo:recipient-v2");
    }

    // ---- corrupt record ---------------------------------------------------

    #[test]
    fn corrupt_record_fails_closed_with_store_error() {
        let root = TempRoot::new();
        let intents = "intents-corrupt";
        std::fs::create_dir_all(root.join(Path::new(&format!("{intents}/{AGENT_A}")))).unwrap();
        let key = hex_key("corrupt-1");
        std::fs::write(
            root.join(Path::new(&format!("{intents}/{AGENT_A}/{key}.json"))),
            "{not json at all",
        )
        .unwrap();
        let mut stats = AgentStats::default();
        let err = scan_agent_intents(&root.join(Path::new(intents)), &a(), &mut stats).unwrap_err();
        assert_eq!(err, StatsError(StatsErrorKind::Store));
    }

    // ---- identity mismatch ----------------------------------------------

    #[test]
    fn identity_mismatch_fails_closed_with_store_error() {
        for id_field in ["\"agent_id\"", "\"idempotency_key\""] {
            let root = TempRoot::new();
            let intents = "intents-mismatch";
            let key = "match-key-1";
            let mut doc = v1_intent(AGENT_A, key, "confirmed", 1, 1, 1, "rlo:x");
            // swap one identity field to a DIFFERENT canonical value
            let payload = serde_json::Value::from_str(&doc).unwrap();
            let mut patched = serde_json::to_value(&payload).unwrap();
            if id_field == "\"agent_id\"" {
                patched["agent_id"] = serde_json::Value::String(AGENT_B.to_string());
            } else {
                patched["idempotency_key"] = serde_json::Value::String("other-key".to_string());
            }
            std::fs::create_dir_all(root.join(Path::new(&format!("{intents}/{AGENT_A}")))).unwrap();
            std::fs::write(
                root.join(Path::new(&format!(
                    "{intents}/{AGENT_A}/{}.json",
                    hex_key(key)
                ))),
                patched.to_string(),
            )
            .unwrap();
            let mut stats = AgentStats::default();
            let err =
                scan_agent_intents(&root.join(Path::new(intents)), &a(), &mut stats).unwrap_err();
            assert_eq!(err, StatsError(StatsErrorKind::Store));
        }
    }

    // ---- unknown schema ---------------------------------------------------

    #[test]
    fn unknown_schema_version_is_inert() {
        let root = TempRoot::new();
        let intents = "intents-unknown";
        // schema 3: unknown -> inert (skipped), but a VALID v1 partner
        // proves the scan continued past the foreign document
        let unknown_doc = format!(
            r#"{{"schema_version":3,"agent_id":"{AGENT_A}","idempotency_key":"fk","amount_kelvin":999999,"state":"confirmed","created_at":1,"updated_at":1,"recipient":"rlo:nope"}}"#
        );
        std::fs::create_dir_all(root.join(Path::new(&format!("{intents}/{AGENT_A}")))).unwrap();
        std::fs::write(
            root.join(Path::new(&format!(
                "{intents}/{AGENT_A}/{}.json",
                hex_key("fk")
            ))),
            &unknown_doc,
        )
        .unwrap();
        put_intent(
            &root,
            intents,
            AGENT_A,
            "real-1",
            &v1_intent(
                AGENT_A,
                "real-1",
                "confirmed",
                42,
                1_700_000_000,
                1_700_000_001,
                "rlo:partner",
            ),
        );
        let mut stats = AgentStats::default();
        scan_agent_intents(&root.join(Path::new(intents)), &a(), &mut stats).unwrap();
        assert_eq!(
            stats.metrics.total, 1,
            "unknown schema must be inert, never counted"
        );
        assert_eq!(stats.metrics.volume_kelvin, 42);
    }

    // ---- non-hex filenames ------------------------------------------------

    #[test]
    fn non_hex_and_odd_and_uppercase_filenames_are_inert() {
        let root = TempRoot::new();
        let intents = "intents-nonce";
        std::fs::create_dir_all(root.join(Path::new(&format!("{intents}/{AGENT_A}")))).unwrap();
        let dir = root.join(Path::new(&format!("{intents}/{AGENT_A}")));
        for name in ["not-hex-name", "AB12", "a", "0x123", "12.345"] {
            std::fs::write(dir.join(format!("{name}.json")), "{}").unwrap();
        }
        // one REAL hex-named VALID record must still be picked up
        put_intent(
            &root,
            intents,
            AGENT_A,
            "real-key",
            &v1_intent(
                AGENT_A,
                "real-key",
                "confirmed",
                7,
                1_700_000_000,
                1_700_000_001,
                "rlo:ok",
            ),
        );
        let mut stats = AgentStats::default();
        scan_agent_intents(&root.join(Path::new(intents)), &a(), &mut stats).unwrap();
        assert_eq!(stats.metrics.total, 1);
        assert_eq!(stats.metrics.volume_kelvin, 7);
    }

    // ---- deterministic filesystem ordering --------------------------------

    #[test]
    fn listing_is_sorted_by_filename_regardless_of_write_order() {
        let root = TempRoot::new();
        let (agents_dir, intents) = ("agents-order", "intents-order");
        put_agent(&root, agents_dir, AGENT_A, 42, "active");
        put_agent(&root, agents_dir, AGENT_B, 42, "active");
        // Three confirmed slots per agent, minted in a NON-sorted order
        // (zeta first, "10" last) with DISTINCT updated_at values so the
        // newest-first total order is fully determined: the scan must
        // process every directory by sorted filename, never by
        // filesystem enumeration order.
        for id in [AGENT_A, AGENT_B] {
            let mut seq: i64 = 0;
            for key in ["zeta", "beta", "10"] {
                seq += 1;
                put_intent(
                    &root,
                    intents,
                    id,
                    key,
                    &v1_intent(
                        id,
                        key,
                        "confirmed",
                        1,
                        1_700_000_000,
                        1_700_000_500 + seq,
                        "rlo:r",
                    ),
                );
            }
        }
        // core lane: per-agent newest-first timeline, name-sorted scan
        let mut stats_a = AgentStats::default();
        scan_agent_intents(&root.join(Path::new(intents)), &a(), &mut stats_a).unwrap();
        let mut stats_b = AgentStats::default();
        scan_agent_intents(&root.join(Path::new(intents)), &b(), &mut stats_b).unwrap();
        let check = |tl: &[super::ConfirmedSlot], tag: &str| {
            assert_eq!(tl.len(), 3, "{tag}: three slots in the timeline");
            assert_eq!(tl[0].at, 1_700_000_503, "{tag}: newest-first total order");
            assert_eq!(tl[1].at, 1_700_000_502);
            assert_eq!(tl[2].at, 1_700_000_501);
        };
        check(&final_timeline(&stats_a), "agent A");
        check(&final_timeline(&stats_b), "agent B");

        // owner lane: volumes tied (3e0), last tied, confirmed tied,
        // distinct agent_id ASC -> deterministic row order A, B
        let (aggregate, rows) = render_owner_stats_in(
            &root.join(Path::new(agents_dir)),
            &root.join(Path::new(intents)),
            42,
        )
        .unwrap();
        assert!(rows.is_empty());
        let agents_arr = aggregate["agents"].as_array().unwrap();
        assert_eq!(
            agents_arr.len(),
            2,
            "deterministic row order must carry both agents"
        );
        assert_eq!(agents_arr[0]["agent_id"], AGENT_A);
        assert_eq!(agents_arr[1]["agent_id"], AGENT_B);
    }

    // ---- privacy: projections carry no forbidden material -----------------

    #[test]
    fn projections_carry_no_forbidden_material() {
        let root = TempRoot::new();
        let (agents_dir, intents) = ("agents-pv", "intents-pv");
        put_agent(&root, agents_dir, AGENT_A, 42, "active");
        put_intent(
            &root,
            intents,
            AGENT_A,
            "pv-key",
            &v1_intent(
                AGENT_A,
                "pv-key",
                "confirmed",
                1,
                1_700_000_000,
                1_700_000_001,
                "rlo:private-channel-recipient",
            ),
        );
        let (aggregate, rows) = render_owner_stats_in(
            &root.join(Path::new(agents_dir)),
            &root.join(Path::new(intents)),
            42,
        )
        .unwrap();
        assert!(rows.is_empty());
        let view = render_agent_stats_in(
            &root.join(Path::new(intents)),
            &a(),
            "a",
            AgentStatus::Active,
            true,
        )
        .unwrap();
        let rendered = format!("{aggregate}\n{view}");
        for forbidden in [
            "owner_user_id",
            "request_fingerprint",
            "idempotency_key",
            "agent_wallet",
            "keypair",
            "secret", // recipient is public data, but the fixture's "secret-" marker must not echo
        ] {
            assert!(
                !rendered.contains(forbidden),
                "projection leaked {forbidden:?}"
            );
        }
        // the decoded key tie-break is INTERNAL: it must never reach the DTO
        assert!(!rendered.contains(hex_key("pv-key").as_str()));
        // the internal projection ALSO must not carry owner_user_id / keypair
        // (field-level audit of the struct's Debug rendering)
        let mut stats = AgentStats::default();
        scan_agent_intents(&root.join(Path::new(intents)), &a(), &mut stats).unwrap();
        let dbg = format!("{stats:?}");
        assert!(!dbg.contains("owner_user_id"));
        assert!(!dbg.contains("keypair"));
    }

    // ---- timeline: confirmed-only + unbounded (core never caps) -----------

    /// Part 2.3: the timeline holds EXACTLY the confirmed/reconciled_paid
    /// slots (never pending/failed/unknown/reconciled_absent) and the
    /// read-only core is UNBOUNDED — the newest-50 HTTP cap is a Part 4/5
    /// DTO-boundary concern and must not appear in the core. Every
    /// non-confirmed state must be inert to the timeline.
    #[test]
    fn timeline_is_confirmed_only_and_core_is_unbounded() {
        let root = TempRoot::new();
        let intents = "intents-co";
        // six distinct states, all with the SAME updated_at tie-broken by
        // distinct identities, so state-filtering is isolated from anything
        // that depends on order
        for (i, state) in [
            "pending",
            "confirmed",
            "failed",
            "unknown",
            "reconciled_paid",
            "reconciled_absent",
        ]
        .iter()
        .enumerate()
        {
            let key = format!("co-{i}");
            put_intent(
                &root,
                intents,
                AGENT_A,
                &key,
                &v1_intent(
                    AGENT_A,
                    &key,
                    state,
                    1_000_000_000,
                    1_700_000_000 + i as i64,
                    1_701_000_000 + i as i64,
                    "rlo:x",
                ),
            );
        }
        let mut stats = AgentStats::default();
        scan_agent_intents(&root.join(Path::new(intents)), &a(), &mut stats).unwrap();
        let tl = final_timeline(&stats);
        // exactly TWO slots: confirmed + reconciled_paid
        assert_eq!(
            tl.len(),
            2,
            "only confirmed + reconciled_paid land in the timeline"
        );
        let states: Vec<&str> = tl.iter().map(|s| s.state).collect();
        assert!(
            states
                .iter()
                .all(|s| *s == "confirmed" || *s == "reconciled_paid"),
            "timeline must contain only confirmed/reconciled_paid: {states:?}"
        );
        // the four non-confirmed states must NEVER appear
        for absent in ["pending", "failed", "unknown", "reconciled_absent"] {
            assert!(
                !states.contains(&absent),
                "{absent} leaked into the timeline"
            );
        }
        // the UNBOUNDED internal projection keeps every confirmed slot
        assert_eq!(stats.timeline.len(), 2, "core projection is unbounded");

        // and a 120-slot ledger (2x the Part 4/5 HTTP cap) must come back
        // entirely through the core — the cap is applied at the DTO layer,
        // never here
        let intents120 = "intents-c120";
        for i in 0..120 {
            let key = format!("c120-{i:03}");
            put_intent(
                &root,
                intents120,
                AGENT_A,
                &key,
                &v1_intent(
                    AGENT_A,
                    &key,
                    "confirmed",
                    1,
                    1_700_000_000 + i,
                    1_700_000_100 + i,
                    "rlo:r",
                ),
            );
        }
        let mut stats120 = AgentStats::default();
        scan_agent_intents(&root.join(Path::new(intents120)), &a(), &mut stats120).unwrap();
        // the internal projection keeps every slot; the rendered timeline is
        // capped to the newest TIMELINE_MAX AFTER deterministic ordering
        assert_eq!(
            stats120.timeline.len(),
            120,
            "internal projection is unbounded"
        );
        let capped = final_timeline(&stats120);
        assert_eq!(
            capped.len(),
            TIMELINE_MAX,
            "timeline is capped to TIMELINE_MAX"
        );
        assert_eq!(
            capped[0].at,
            1_700_000_100 + 119,
            "newest slot survives the cap"
        );
        assert_eq!(
            capped[TIMELINE_MAX - 1].at,
            1_700_000_100 + 70,
            "oldest in the 50"
        );
    }

    /// Part 2.3 ORDER: `updated_at DESC`, then the deterministic identity
    /// ASC. The tie-break must be the stored identity itself — a distinct
    /// identity always separates a full updated_at tie — so the order is
    /// total and reproducible independent of anything else.
    #[test]
    fn timeline_updates_at_desc_then_identity_asc() {
        let root = TempRoot::new();
        let intents = "intents-tie";
        // two slots tie on updated_at (both 1_701_000_004); identity decides:
        // hex "aa" < hex "cc"  =>  the "aa" identity sorts FIRST (ASC)
        put_intent(
            &root,
            intents,
            AGENT_A,
            "tie-newest-aa",
            &v1_intent(
                AGENT_A,
                "tie-newest-aa",
                "confirmed",
                1,
                1_700_000_000,
                1_701_000_004,
                "rlo:a",
            ),
        );
        put_intent(
            &root,
            intents,
            AGENT_A,
            "tie-newest-cc",
            &v1_intent(
                AGENT_A,
                "tie-newest-cc",
                "reconciled_paid",
                1,
                1_700_000_001,
                1_701_000_004,
                "rlo:b",
            ),
        );
        // an older confirmed slot sorts LAST
        put_intent(
            &root,
            intents,
            AGENT_A,
            "tie-oldest",
            &v1_intent(
                AGENT_A,
                "tie-oldest",
                "confirmed",
                1,
                1_699_000_000,
                1_699_000_500,
                "rlo:c",
            ),
        );
        let mut stats = AgentStats::default();
        scan_agent_intents(&root.join(Path::new(intents)), &a(), &mut stats).unwrap();
        let tl = final_timeline(&stats);
        // newest-first: the two 1_701_000_004 slots first (identity ASC: aa before cc),
        // then the 1_699_000_500 slot
        assert_eq!(tl.len(), 3);
        assert_eq!(tl[0].at, 1_701_000_004);
        assert_eq!(tl[1].at, 1_701_000_004);
        assert_eq!(tl[2].at, 1_699_000_500);
        // identity ASC within the tie: the "aa" identity precedes the "cc" identity
        assert_eq!(tl[0].deterministic_identity, hex_key("tie-newest-aa"));
        assert_eq!(tl[1].deterministic_identity, hex_key("tie-newest-cc"));
    }

    /// Part 2.3 CAP: the rendered timeline is capped to the newest
    /// TIMELINE_MAX (50) AFTER deterministic ordering — a deterministic,
    /// reproducible bound that never leaks filesystem enumeration order
    /// into the output.
    #[test]
    fn timeline_is_bounded_to_fifty_newest() {
        let root = TempRoot::new();
        let intents = "intents-cap50";
        // Mint 80 confirmed slots with strictly increasing updated_at:
        // the deterministic total order is fully determined by `at DESC`
        // alone (no identity ties), so the capped output is the newest 50
        // in updated_at DESC order, independent of directory enumeration.
        for i in 0..80 {
            let key = format!("cap50-{i:03}");
            put_intent(
                &root,
                intents,
                AGENT_A,
                &key,
                &v1_intent(
                    AGENT_A,
                    &key,
                    "confirmed",
                    1,
                    1_700_000_000 + i,
                    1_700_000_1000 + i,
                    "rlo:cap",
                ),
            );
        }
        let mut stats = AgentStats::default();
        scan_agent_intents(&root.join(Path::new(intents)), &a(), &mut stats).unwrap();
        // internal projection: all 80
        assert_eq!(stats.timeline.len(), 80, "internal projection is unbounded");
        let tl = final_timeline(&stats);
        // rendered timeline: exactly TIMELINE_MAX (50)
        assert_eq!(tl.len(), TIMELINE_MAX, "timeline is capped to TIMELINE_MAX");
        // the newest 50: updated_at 1_700_001_000 + 79 down to + 30
        assert_eq!(tl[0].at, 1_700_000_1000 + 79, "newest slot survives");
        assert_eq!(tl[49].at, 1_700_000_1000 + 30, "oldest in the capped 50");
        // every slot in the capped timeline must be at least as recent as
        // tl[49] — nothing before the boundary leaks in
        for (idx, slot) in tl.iter().enumerate() {
            assert!(slot.at >= tl[49].at, "slot {idx} predates the cap boundary");
        }
    }

    // ---- read-only proof: zero mutation, zero debris ----------------------

    #[test]
    fn scans_are_read_only_and_leave_no_debris() {
        let root = TempRoot::new();
        let (agents_dir, intents) = ("agents-ro", "intents-ro");
        put_agent(&root, agents_dir, AGENT_A, 42, "active");
        put_agent(&root, agents_dir, AGENT_B, 42, "draft");
        put_intent(
            &root,
            intents,
            AGENT_A,
            "ro-1",
            &v1_intent(
                AGENT_A,
                "ro-1",
                "confirmed",
                5,
                1_700_000_000,
                1_700_000_001,
                "rlo:ro",
            ),
        );
        put_intent(
            &root,
            intents,
            AGENT_B,
            "ro-1",
            &v2_intent(
                AGENT_B,
                "ro-1",
                "reconciled_paid",
                3,
                1_700_000_000,
                1_700_000_002,
                "rlo:ro2",
            ),
        );
        let _ = render_owner_stats_in(
            &root.join(Path::new(agents_dir)),
            &root.join(Path::new(intents)),
            42,
        )
        .unwrap();
        let _ = render_agent_stats_in(
            &root.join(Path::new(intents)),
            &a(),
            "a",
            AgentStatus::Active,
            true,
        )
        .unwrap();
        // Baseline captured immediately AFTER the two normal read-only scans
        // — this is the true "before" state the post-teardown snapshot must
        // match. Taken BEFORE any poison fixture is minted so the corrupt-dir
        // writes stay strictly on one side of the before/after barrier.
        let after = snapshot(&root.0);
        // A corrupt TRUSTED agent-metadata record must fail closed with
        // Store, carry no partial data, and leave the tree byte-identical.
        // (Minted fresh under a DEDICATED agents dir — the agent scan reads
        // every <uuid>.json via the authoritative reader.)
        let corrupt_agents_dir = root.join(Path::new(&format!("{agents_dir}-corrupt")));
        std::fs::create_dir_all(&corrupt_agents_dir).unwrap();
        let poison = corrupt_agents_dir.join(format!("{AGENT_A}.json"));
        std::fs::write(&poison, "{broken").unwrap();
        let owner_err =
            render_owner_stats_in(&corrupt_agents_dir, &root.join(Path::new(intents)), 42)
                .expect_err("a corrupt trusted record must fail closed with Store");
        assert_eq!(owner_err, StatsError(StatsErrorKind::Store));
        // A corrupt TRUSTED intent slot (a hex-named intent whose bytes are
        // garbage) must ALSO fail closed with Store — the scan layer is
        // covered independently of the agent-record layer above.
        let corrupt_slots_dir = root.join(Path::new(&format!("{intents}-corrupt-slot")));
        std::fs::create_dir_all(&corrupt_slots_dir.join(Path::new(AGENT_A))).unwrap();
        let slot_poison = corrupt_slots_dir
            .join(Path::new(AGENT_A))
            .join(format!("{}.json", hex_key("slot-pois")));
        std::fs::write(&slot_poison, "{broken").unwrap();
        let mut stats_poisoned = AgentStats::default();
        let err = scan_agent_intents(&corrupt_slots_dir, &a(), &mut stats_poisoned)
            .expect_err("a corrupt trusted record must fail closed with Store");
        assert_eq!(err, StatsError(StatsErrorKind::Store));
        assert!(
            stats_poisoned.timeline.is_empty(),
            "no partial readout may ride along with the Store error"
        );
        // (the before/after barrier is the `after` snapshot captured above,
        // before any poison fixture existed; see the read-only assertions below)
        // test-side teardown of its own fixtures; the core never removed
        // any of them
        let _ = std::fs::remove_file(&poison);
        let _ = std::fs::remove_dir_all(&corrupt_agents_dir);
        let _ = std::fs::remove_file(&slot_poison);
        let _ = std::fs::remove_dir_all(&corrupt_slots_dir);
        let final_snapshot = snapshot(&root.0);
        assert_eq!(
            after.1, final_snapshot.1,
            "no new directory entries remain after all scans"
        );
        // The read-only guarantee: taken AFTER all test-side fixtures are
        // torn down, `final` must be byte-identical to the tree as it stood
        // after the normal owner/per-agent scans (before.0 = before.1).
        let before = after.clone();
        assert_eq!(
            before.0.clone(),
            final_snapshot.0,
            "byte-identical tree after all scans"
        );
        assert_eq!(
            before.1, final_snapshot.1,
            "no debris (temp/rename residue) left behind"
        );
    }

    // ---- structural: the core is read-only and network/wallet-free --------

    /// The established pattern from activity.rs: split the source, strip
    /// comments (so prose about the boundaries never trips the token scan),
    /// and assert on the READ-ONLY CORE: no fs mutation API, no HTTP
    /// surface, no wallet / RPC / config / payment identifiers. Fixtures in
    /// the tests module are intentionally excluded — they mint and clean up
    /// temp trees on purpose; the core is what must stay pure. The
    /// credential-lane privacy gate + handlers (Part 2.5.x) sit AFTER the
    /// core and are excluded from this structural scan: the gate's whole job
    /// is to NAME and probe the forbidden identifiers (its key-name/path/
    /// value spec), so it must reference them — that lane's privacy
    /// guarantee is enforced behaviorally by the Part 2.5.2 black-box tests
    /// instead.
    #[test]
    fn core_is_read_only_and_network_and_wallet_free() {
        let src = include_str!("stats.rs");
        // Split at the credential-lane privacy gate's doc line (the 2.5.2
        // boundary), NOT at `#[cfg(test)]`: the gate and the handlers below
        // it legitimately name the forbidden identifiers by design. The
        // anchor is the gate's unique first doc line, so the core section
        // arrives intact.
        let core = src
            .split_inclusive("\n/// The credential-lane absence gate (Part 2.5.2).")
            .next()
            .unwrap();
        let stripped: String = core
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !(t.starts_with("//") || t.starts_with("///") || t.starts_with("//!"))
            })
            .collect::<Vec<_>>()
            .join("\n");
        // 1) the ONLY filesystem surface allowed in production code
        for allowed in ["read_dir", "fs::read"] {
            assert!(
                stripped.contains(allowed),
                "core must actually scan directories (expected: {allowed})"
            );
        }
        // 2) NO fs mutation API anywhere in production code
        for forbidden in [
            "fs::write",
            "File::create",
            "OpenOptions",
            "create_dir",
            "create_file",
            "remove_",
            "rename(",
            "copy(",
            "hard_link",
            "set_permissions",
            "set_len",
            "remove_dir",
        ] {
            assert!(
                !stripped.contains(forbidden),
                "core must not touch an fs mutation API: {forbidden}"
            );
        }
        // 3) the route wiring lives in server.rs (the literal
        //    `/api/agents/stats` registered before the parameterized
        //    family, see Part 2.3) — the handlers themselves carry the
        //    axum surface, so only the structural declarations are banned.
        for forbidden in ["Router", ".route(", ".nest(", ".merge("] {
            assert!(
                !stripped.contains(forbidden),
                "core must not declare an HTTP surface: {forbidden}"
            );
        }
        // 4) NO wallet / network / config / payment identifiers.
        //    NOTE: `owner_user_id` is deliberately ABSENT from this list —
        //    the owner filter above reads the `Agent::owner_user_id` field,
        //    so the name cannot be banned from the production source. The
        //    corresponding privacy guarantee (owner_user_id must never reach
        //    the SERIALIZED projections) is asserted at the DTO level in
        //    `projections_carry_no_forbidden_material`, which is the
        //    guarantee that actually matters.
        for forbidden in [
            "wallet", // agent_wallets / wallets / wallet paths
            "reqwest",
            "RialoConfig",
            "PaymentOps",
            "request_fingerprint",
            "idempotency_key",
            "keypair",
            "Signer",
        ] {
            assert!(
                !stripped.contains(forbidden),
                "core must not name a wallet/network/payment identifier: {forbidden}"
            );
        }
        // 5) the source must still carry the focused scenario suite (a
        // missing scenario is a missing guarantee)
        for expected in [
            "missing_directories_yield_empty_projections_not_errors",
            "valid_v1_confirmed_lands_in_metrics_timeline_and_day_bucket",
            "valid_v2_confirmed_maps_through_v2_to_canonical",
            "corrupt_record_fails_closed_with_store_error",
            "identity_mismatch_fails_closed_with_store_error",
            "unknown_schema_version_is_inert",
            "non_hex_and_odd_and_uppercase_filenames_are_inert",
            "listing_is_sorted_by_filename_regardless_of_write_order",
            "projections_carry_no_forbidden_material",
            "timeline_is_bounded_to_fifty_newest",
            "scans_are_read_only_and_leave_no_debris",
        ] {
            assert!(
                src.contains(expected),
                "the required scenario test exists: {expected}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// PHASE 7 — AGENT STATS · PART 2.3 — focused API / auth tests (routes).
//
// A SEPARATE test file (included via `#[path]` here): the real production
// Router is exercised IN-PROCESS against a fresh `TcpListener` per request
// to nail down the ROUTE surface — auth gate, owner isolation, the
// single-agent choke point, store-corruption -> 500, valid empty store ->
// 200 zero/empty/null, and the literal-vs-`{id}` route order. See the
// module doc in _stats24_tests.rs for the full shape.
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "_stats24_tests.rs"]
pub(crate) mod tests24;

// ---------------------------------------------------------------------------
// PHASE 7 — AGENT STATS · PART 2.5.1 — credential lane, minimal route
// compilation tests (the full privacy test matrix is a LATER part).
//
// A SEPARATE test file (included via `#[path]` here): the real
// production handler (`agent_trigger_stats`) is mounted on the EXACT
// route set + order server.rs registers and exercised IN-PROCESS with
// a real Argon2id-backed credential minted through the EXISTING
// `agent_credentials::issue_in` helper. See the module doc in
// _stats251_tests.rs for the full shape.
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "_stats251_tests.rs"]
pub(crate) mod tests251;

// ---------------------------------------------------------------------------
// PHASE 7 — AGENT STATS · PART 2.5.2 — credential-lane PRIVACY HARDENING
// tests (the full privacy matrix).
//
// A SEPARATE test file (included via `#[path]` here): the real production
// handler (`agent_trigger_stats`) mounted on the EXACT route set + order
// server.rs registers, exercised IN-PROCESS against fresh temp trees with
// a rich, deliberately secret-bearing fixture, proving every forbidden
// field AND value marker is absent from the 200 credential-lane body —
// plus the cross-agent isolation, agent_id-injection, store-integrity
// gates (404/500), empty-agent, determinism, and owner/session-lane
// regression checks. See the module doc in _stats252_tests.rs.
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "_stats252_tests.rs"]
pub(crate) mod tests252;
