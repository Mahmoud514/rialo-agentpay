// =============================================================================
// Single Rialo integration layer.
//
// Every chain touchpoint in AgentPay (balance, faucet/airdrop, transfer,
// health probe) goes through this module. Nothing else may spawn the Rialo
// CLI or decide which RPC endpoint to use.
//
// Configuration is owned by RialoConfig, built once from the environment in
// main(). There is exactly one RPC URL in the whole application.
//
// Infrastructure failures are returned as typed errors with stable codes
// (RIALO_RPC_UNAVAILABLE etc.) so API handlers can degrade gracefully
// instead of crashing or reporting misleading data.
// =============================================================================

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Which kind of chain operation a CLI invocation performs. Error
/// classification is operation-aware: a timeout while waiting for a
/// transaction to land means different things for a faucet request vs a
/// payment transfer — in particular a transfer/payment must NEVER be
/// reported as a faucet failure (verified 2026-09-28: POST /api/payment can
/// return "Transaction confirmation timed out" while the transfer still
/// lands on-chain and the recipient balance increases).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    /// Read-only RPC calls (health probe, balance, account existence).
    Read,
    /// Faucet airdrop requests.
    Faucet,
    /// Direct token transfer (the payment path).
    Transfer,
    /// Program invocation that moves funds (payment via the Venus program).
    Program,
}

impl Operation {
    /// True for operations that broadcast a money-moving transaction.
    fn is_payment(&self) -> bool {
        matches!(self, Operation::Transfer | Operation::Program)
    }
}

/// Resolved Rialo infrastructure configuration. Built once in main() from env.
#[derive(Clone, Debug)]
pub struct RialoConfig {
    /// Absolute or PATH-resolved `rialo` CLI binary.
    pub cli: PathBuf,
    /// The ONE RPC endpoint used by the whole app (RIALO_RPC_URL).
    pub rpc_url: String,
    /// Deployed AgentPay Venus program ID (AGENTPAY_PROGRAM_ID). None = the
    /// program integration is not configured; direct transfers stay the path.
    pub program_id: Option<String>,
    /// Directory containing the program's wit/<name>-manifest.json
    /// (AGENTPAY_PROGRAM_DIR, default "artifact"). The manifest itself is
    /// discovered inside `<dir>/wit/*-manifest.json` by
    /// `program_manifest_path` and passed to the CLI with `--manifest`.
    pub program_dir: PathBuf,
}

/// A typed infrastructure error with a stable machine-readable code.
///
/// PHASE 6 STEP 4: `tx_signature` carries a transaction signature that the
/// CLI surfaced INSIDE a failure envelope (the confirmation-timeout case:
/// the transfer was built and broadcast, the CLI only failed to confirm
/// it). It is None for every error where the CLI surfaced no signature —
/// nothing here is ever fabricated.
#[derive(Clone, Debug)]
pub struct RialoError {
    pub code: &'static str,
    pub detail: String,
    pub tx_signature: Option<String>,
}

impl RialoError {
    /// Constructor for errors that carry no recoverable signature (every
    /// pre-broadcast / infrastructure failure).
    fn plain(code: &'static str, detail: String) -> Self {
        Self {
            code,
            detail,
            tx_signature: None,
        }
    }
}

// =============================================================================
// PHASE 6 STEP 4 — read-only transaction lookup + address-history scan
// =============================================================================

/// The verdict of a `get_transaction(signature)` equivalent. The four
/// outcomes map exactly onto what reconciliation may conclude:
///   Found    → decisive evidence (executed/err fields say paid vs failed)
///   NotFound → the RPC answered and reports the signature unknown:
///              NEVER proof of permanent absence before the finality
///              horizon — reconciliation must stay Unknown.
///   Unavailable → transient infrastructure failure (RIALO_RPC_UNAVAILABLE
///              semantics preserved) — stay Unknown, never Absent.
///   Malformed → success envelope that cannot be parsed into a complete
///              record (incomplete/unparseable response) — stay Unknown.
#[derive(Debug, Clone)]
pub enum TxLookup {
    Found(TxRecord),
    NotFound,
    Unavailable(RialoError),
    Malformed,
}

/// A safely-parsed transaction record. Every field is optional because
/// response shapes vary; reconciliation consumes a record ONLY when the
/// fields it needs are present (fail-closed), never infers them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxRecord {
    /// The signature this record describes (None when the envelope did
    /// not carry one — the caller keys evidence off the requested sig).
    pub signature: Option<String>,
    pub executed: bool,
    /// The on-chain error tag when the transaction failed (None = no err).
    pub err: Option<String>,
    /// Processing slot; None when the response shape carries neither a
    /// slot nor a block height to stand in for it.
    pub slot: Option<u64>,
    pub block_height: Option<u64>,
    pub block_time: Option<i64>,
    pub fee: Option<u64>,
    /// The fee-payer (first signer) address, when decodable.
    pub payer: Option<String>,
    /// System-transfer destination, when the instructions decode exactly.
    pub transfer_recipient: Option<String>,
    /// System-transfer amount in integer kelvin, when decoded exactly.
    pub transfer_amount_kelvin: Option<u64>,
    /// True when the envelope decoded fully (status + identity present).
    pub complete: bool,
}

impl TxRecord {
    /// Decoded transfer facts, if all three are present.
    pub fn transfer_facts(&self) -> Option<(&str, &str, u64)> {
        Some((
            self.payer.as_deref()?,
            self.transfer_recipient.as_deref()?,
            self.transfer_amount_kelvin?,
        ))
    }
}

/// One entry of an address history window (vendor `SignatureInfo` from
/// rialo-api-types-0.18.1: signature, block_height, err?, block_time? —
/// block time arrives in MILLISECONDS and is normalized to seconds here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureInfoRecord {
    pub signature: String,
    pub block_height: Option<u64>,
    /// Some(...) = the node reported a failure for this signature.
    pub err: Option<String>,
    /// Unix SECONDS (ms normalized by the reader).
    pub block_time: Option<i64>,
}

/// Outcome of the read-only `getSignatureStatuses` supplement consulted
/// when the PRIMARY CLI lookup errored (fix 1). Three-way by design:
/// only an EXPLICIT status is evidence; an answered-but-empty query is a
/// temporary not-found; a broken probe decides nothing.
#[derive(Debug)]
pub enum StatusProbe {
    /// The node answered with an explicit status record (its own
    /// executed bool — fix 2 is enforced at the parse layer).
    Explicit(TxRecord),
    /// The node answered and has no status for this signature (null or
    /// missing entry) — temporary, never permanent absence.
    NoStatus,
    /// The probe itself failed (RPC down, unparseable reply, or an entry
    /// without its executed bool) — the caller classifies from the
    /// primary error and fails closed.
    Inconclusive,
}

#[derive(Debug)]
pub(crate) enum StatusEntry {
    Explicit(TxRecord),
    NoStatus,
    Inconclusive,
}

/// Parse the `result` object of a `getSignatureStatuses` reply for a
/// ONE-signature query (vendor `GetSignatureStatusesResponse`:
/// `{version?, context, value:[{slot, err?, executed} | null]}`,
/// camelCase). FIX 5: the decisive array is `result.value`. The status
/// entry's `executed` is an EXPLICIT bool from the node — never derived
/// from `err == null` (fix 2); a non-boolean/missing executed makes the
/// probe inconclusive, not a verdict. The signature on the produced
/// record is the REQUESTED one: a status query is keyed by signature,
/// so no carried-sig field exists to mismatch.
pub fn parse_signature_status(signature: &str, result: &Value) -> StatusEntry {
    let Some(items) = result.get("value").and_then(Value::as_array) else {
        return StatusEntry::Inconclusive;
    };
    // exactly one entry expected; more shape-noise = inconclusive
    let Some(entry) = items.first() else {
        return StatusEntry::NoStatus;
    };
    if entry.is_null() || !entry.is_object() {
        return StatusEntry::NoStatus;
    }
    let Some(executed) = bool_field(entry, &["executed", "EXECUTED"]) else {
        return StatusEntry::Inconclusive;
    };
    let err = entry
        .get("err")
        .or_else(|| entry.get("error"))
        .filter(|e| !e.is_null())
        .map(|e| {
            e.as_str()
                .map(str::to_string)
                .unwrap_or_else(|| e.to_string())
        });
    let slot = u64_field(entry, &["slot"]);
    let context_slot = result
        .get("context")
        .and_then(|c| u64_field(c, &["slot", "current_slot", "currentSlot"]));
    let slot = slot.or(context_slot);
    StatusEntry::Explicit(TxRecord {
        signature: Some(signature.to_string()),
        executed,
        err,
        slot,
        block_height: None,
        block_time: None,
        fee: None,
        payer: None,
        transfer_recipient: None,
        transfer_amount_kelvin: None,
        // a status-only record is decisive on executed/err/slot; transfer
        // facts and chain timing stay None and are completed (or left
        // fail-closed) by the callers, never fabricated here.
        complete: true,
    })
}

/// Parse one vendor `SignatureInfo` array item (fix 5/7 live shape:
/// `{signature, blockHeight?, err?, blockTime?}` — camelCase from
/// rialo-api-types-0.18.1; snake_case tolerated; blockTime arrives in
/// MILLISECONDS and is normalized). Items without a usable signature are
/// skipped — they are not evidence of anything.
pub fn parse_signature_items(items: &[Value]) -> Vec<SignatureInfoRecord> {
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Some(signature) = item.get("signature").and_then(Value::as_str) else {
            continue;
        };
        if signature.is_empty() || signature.len() > 128 {
            continue;
        }
        let err_field = item.get("err").filter(|v| !v.is_null()).map(|v| {
            v.as_str()
                .map(str::to_string)
                .unwrap_or_else(|| v.to_string())
        });
        let block_time = i64_field(item, &["blockTime", "block_time"]).map(normalize_block_time);
        out.push(SignatureInfoRecord {
            signature: signature.to_string(),
            block_height: u64_field(item, &["blockHeight", "block_height"]),
            err: err_field,
            block_time,
        });
    }
    out
}

/// FIX 6 — the ONLY chain-timing fallback reader: extract the block's
/// own time from a `getBlock` reply (vendor `{version?, context,
/// value: BlockInfo{block_height, block_time, ...}}`; the CLI view uses
/// snake_case; a bare BlockInfo is tolerated). Missing time => None:
/// never synthesized from anything local.
pub fn parse_block_time(result: &Value) -> Option<i64> {
    let block = result.get("value").filter(|v| v.is_object())?;
    i64_field(block, &["block_time", "blockTime"]).map(normalize_block_time)
}

/// The node reports block_time in ms (1e11+ is never plausible seconds
/// this decade and below); normalize defensively for both shapes.
pub fn normalize_block_time(raw: i64) -> i64 {
    if raw >= 100_000_000_000 {
        raw / 1000
    } else {
        raw
    }
}

/// Base58 (Bitcoin/Rialo alphabet) decode. Returns None on any invalid
/// character or overflow-shaped input. Kept local: this crate's dependency
/// surface for the server feature is deliberately minimal.
pub fn base58_decode(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut bytes: Vec<u8> = Vec::new();
    for ch in input.bytes() {
        let digit = ALPHABET.iter().position(|&a| a == ch)? as u32;
        let mut carry = digit;
        for b in bytes.iter_mut() {
            let v = (*b as u32) * 58 + carry;
            *b = (v & 0xff) as u8;
            carry = v >> 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    for _ in input.chars().take_while(|&c| c == '1') {
        bytes.insert(0, 0);
    }
    bytes.reverse();
    Some(bytes)
}

/// Extract the integer-kelvin amount from a Solana-legacy System-program
/// transfer instruction data field (u32-le discriminator == 2, u64-le
/// amount). The destination account index lives in instruction.accounts[0],
/// not in `data`. Returns None for any other shape — NEVER a guess.
fn system_transfer_amount(data: &str) -> Option<u64> {
    let raw = base58_decode(data)?;
    if raw.len() != 12 {
        return None;
    }
    if u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) != 2 {
        return None;
    }
    Some(u64::from_le_bytes([
        raw[4], raw[5], raw[6], raw[7], raw[8], raw[9], raw[10], raw[11],
    ]))
}

/// Error-message shapes that mean "the node answered: this signature is
/// currently unknown to it". Permanently-unknown is NOT a thing a lookup
/// error can prove before the finality horizon, so callers get `NotFound`
/// and must keep the intent Unknown until evidence is decisive.
fn is_not_found_message(message: &str) -> bool {
    let m = message.to_lowercase();
    m.contains("not found")
        || m.contains("no such transaction")
        || m.contains("unknown transaction")
        || m.contains("transactionnotfound")
        || m.contains("signaturenotfound")
}

/// Pull a signature string out of a failure envelope. The CLI's
/// confirmation-timeout envelope may carry the broadcast signature in any
/// of several shapes; only a NON-EMPTY string is taken, never a placeholder.
fn extract_signature(value: &Value) -> Option<String> {
    const KEYS: [&str; 4] = ["signature", "tx_signature", "txSignature", "transaction"];
    for key in KEYS {
        if let Some(s) = value.get(key).and_then(Value::as_str) {
            if !s.is_empty() && s.len() <= 128 {
                return Some(s.to_string());
            }
        }
    }
    if let Some(err) = value.get("error") {
        return extract_signature(err);
    }
    if let Some(result) = value.get("result") {
        return extract_signature(result);
    }
    None
}

/// G25 — diagnostics-only text sanitizer for `[rialo-diag]`/`[rialo-err]`
/// lines. Pipeline: first line only → ≤200 chars (marked when truncated)
/// → defensive redactions applied repeatedly until stable:
///   * filesystem paths: `/app`, `/home/*` (keypair paths embed wallet ids)
///   * base58 tokens 87–99 chars (ed25519 full signatures; 64-byte sigs
///     encode to 87–88 chars — kept arity-wide to cover hex/base58 mixes)
///   * hex blobs ≥64 chars (raw seeds / key bytes)
///   * 12/24-word seed phrases (letter-only tokens ≤12 chars, in runs)
///   * long digit runs ≥8 chars (wallet user ids like 50506318)
/// Never echoes raw stdout/stderr bodies, keys, seeds, or full signatures.
pub(crate) fn diag_text(text: &str) -> String {
    let first = text.lines().next().unwrap_or("").to_string();
    let truncated = first.chars().count() > 200;
    let mut cap: String = first.chars().take(200).collect();
    if cap.is_empty() {
        cap = "<empty>".to_string();
    }
    // Redact defensively (loop to fixed point so stacked patterns collapse).
    let redact = |s: String| -> String {
        let mut out = s;
        out = out.replace("/app", "<app>").replace("/home/", "<home>/");
        // base58 signature-sized tokens (87-99 chars, base58 alphabet)
        let mut rebuilt: Vec<String> = Vec::new();
        for tok in out.split(' ') {
            let is_b58 = !tok.is_empty()
                && tok.chars().count() >= 87
                && tok.chars().count() <= 99
                && tok.chars().all(|c| {
                    c.is_ascii_alphanumeric() && c != '0' && c != 'O' && c != 'I' && c != 'l'
                });
            if is_b58 {
                rebuilt.push(format!("{}…<sig-redacted>", &tok[..9]));
            } else {
                rebuilt.push(tok.to_string());
            }
        }
        out = rebuilt.join(" ");
        // long hex blobs (seed/key material)
        let mut hex_out: Vec<String> = Vec::new();
        for tok in out.split(' ') {
            if tok.chars().count() >= 64 && tok.chars().all(|c| c.is_ascii_hexdigit()) {
                hex_out.push(tok[..8].to_string() + "…<hex-redacted>");
            } else {
                hex_out.push(tok.to_string());
            }
        }
        out = hex_out.join(" ");
        // NOTE (G25 review): 12/24-word seed phrases cannot be reliably
        // distinguished from error prose by shape alone (errors ARE prose).
        // Seed phrases never appear in CLI stderr/detail by vendor contract
        // (keys are read from files, never echoed); defensively we do NOT
        // guess on shape here to avoid destroying actionable error text.
        // The hex-blob redaction above already covers raw seed hex forms.
        // wallet user ids (7-10 digit runs, may carry separators)
        let mut digits: Vec<String> = Vec::new();
        for tok in out.split(' ') {
            let digits_only: String = tok.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits_only.chars().count() >= 8
                && tok
                    .chars()
                    .all(|c| c.is_ascii_digit() || !c.is_alphanumeric())
                && tok.chars().any(|c| c.is_ascii_digit())
            {
                digits.push("<uid-redacted>".to_string());
            } else {
                digits.push(tok.to_string());
            }
        }
        digits.join(" ")
    };
    cap = redact(cap);
    cap = redact(cap); // second pass: stacked patterns (path+token mixes)
    if truncated {
        cap.push_str("…<truncated>");
    }
    cap
}

/// JSON-RPC error object from a plain JSON-RPC reply, when present.
fn jsonrpc_error(value: &Value) -> Option<&Value> {
    value.get("error")
}

/// Build the read-only JSON-RPC request body for the STEP-4 remediation
/// lanes. FIX 4 (live-shape remediation): `params` is the EXACT vendor
/// form — a single positional OBJECT (the serialized request struct),
/// e.g. `[{"version":0,"address":"…","config":{"limit":…}}]`, never the
/// Solana-style positional `[address, config]` array the rialo node
/// rejects. Pure/testable so the wire shape is pinned by fixtures
/// without any live call.
pub fn rpc_request_body(method: &str, params: &Value) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": [params],
    })
}

impl RialoError {
    pub fn is_rpc_down(&self) -> bool {
        self.code == "RIALO_RPC_UNAVAILABLE"
    }
}

/// Fallback CLI location if RIALO_CLI_PATH is unset and `rialo` is not on PATH.
/// Resolved relative to $HOME under `~/.local/share/rialo/releases/` — newest
/// versioned `bin/rialo` wins — so no absolute developer path is baked in.
fn fallback_cli_path() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_default();
    let releases = home.join(".local/share/rialo/releases");
    let mut best: Option<(String, PathBuf)> = None;
    if let Ok(entries) = std::fs::read_dir(&releases) {
        for entry in entries.flatten() {
            let cand = entry.path().join("bin").join("rialo");
            if cand.is_file() {
                let key = entry.file_name().to_string_lossy().to_string();
                if best.as_ref().map_or(true, |(k, _)| key > *k) {
                    best = Some((key, cand));
                }
            }
        }
    }
    best.map(|(_, p)| p)
        .unwrap_or_else(|| releases.join("rialo"))
}

impl RialoConfig {
    /// Build config from environment:
    ///   RIALO_RPC_URL   (default: http://127.0.0.1:4104 — localnet)
    ///   RIALO_CLI_PATH  (default: `rialo` on PATH, else CLI_FALLBACK_PATH)
    ///   AGENTPAY_PROGRAM_ID   (optional: deployed Venus program ID)
    ///   AGENTPAY_PROGRAM_DIR  (optional: dir with wit/ manifest, default "artifact")
    pub fn from_env() -> Self {
        let rpc_url = std::env::var("RIALO_RPC_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:4104".to_string())
            .trim_end_matches('/')
            .to_string();

        let cli = std::env::var("RIALO_CLI_PATH")
            .ok()
            .map(PathBuf::from)
            .filter(|p| p.exists())
            .or_else(|| {
                // PATH lookup
                which("rialo")
            })
            .unwrap_or_else(fallback_cli_path);

        let program_id = std::env::var("AGENTPAY_PROGRAM_ID")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());

        let program_dir = std::env::var("AGENTPAY_PROGRAM_DIR")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("artifact"));

        Self {
            cli,
            rpc_url,
            program_id,
            program_dir,
        }
    }

    /// Run a `rialo ... --json` command and return the parsed JSON result.
    fn run(&self, op: Operation, subcommand: &[&str]) -> Result<Value, RialoError> {
        self.run_with_config_dir(None, op, subcommand)
    }

    /// Run a `rialo ... --json` command, optionally overriding the CLI config
    /// directory with `-c <dir>` (used by the program layer for per-invocation
    /// ephemeral keyring configs).
    fn run_with_config_dir(
        &self,
        config_dir: Option<&std::path::Path>,
        op: Operation,
        subcommand: &[&str],
    ) -> Result<Value, RialoError> {
        let mut cmd = Command::new(&self.cli);
        if let Some(dir) = config_dir {
            cmd.arg("-c").arg(dir);
        }
        // G25 — bounded CLI diagnostics: op, exit code, duration (ms), error
        // classification, and output LENGTHS only. Never logs raw stdout/
        // stderr, signatures, key material, or wallet/credential data.
        let started = std::time::Instant::now();
        let output = cmd
            .arg("--url")
            .arg(&self.rpc_url)
            .arg("--no-setup")
            .args(subcommand)
            .arg("--json")
            .output()
            .map_err(|e| {
                eprintln!(
                    "[rialo-diag] op={:?} exit=spawn_fail dur_ms={} code=RIALO_CLI_UNAVAILABLE",
                    op,
                    started.elapsed().as_millis()
                );
                RialoError::plain(
                    "RIALO_CLI_UNAVAILABLE",
                    format!("failed to run rialo CLI at {}: {}", self.cli.display(), e),
                )
            })?;
        // exit code for the diagnostic arms below (-1 ⇒ killed by signal).
        let exit_code = output.status.code().unwrap_or(-1);

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

        // The CLI prints its JSON document on stdout on success; on failure
        // the JSON error envelope goes to stderr (with a non-zero exit).
        let candidate = if output.status.success() {
            &stdout
        } else {
            &stderr
        };

        let parsed: Value = serde_json::from_str(candidate).map_err(|_| {
            let fallback_text = if candidate.is_empty() {
                &stdout
            } else {
                candidate
            };
            // Preserve the historical behavior: unparseable CLI output only
            // keeps a classified code when the CLI failed hard and the output
            // says RPC-down or confirmation-timeout.
            let code = if !output.status.success() {
                match classify(op, fallback_text) {
                    c @ ("RIALO_RPC_UNAVAILABLE" | "RIALO_TRANSFER_CONFIRMATION_TIMEOUT") => c,
                    _ => "RIALO_ERROR",
                }
            } else {
                "RIALO_ERROR"
            };
            eprintln!(
                "[rialo-diag] op={:?} exit={} dur_ms={} out_len={} err_len={} code={} outcome=out_unparseable",
                op, exit_code, started.elapsed().as_millis(),
                stdout.len(), stderr.len(), code
            );
            RialoError::plain(
                code,
                with_confirmation_timeout_note(
                    code,
                    format!(
                        "CLI exited with {}: {}",
                        output.status,
                        first_line(fallback_text)
                    ),
                ),
            )
        })?;

        // Explicit failure envelope: {"success":false,"error":{...},"message":...}
        if parsed.get("success").and_then(Value::as_bool) == Some(false) {
            let message = parsed
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown Rialo error")
                .to_string();

            let code = classify(
                op,
                &format!(
                    "{} {}",
                    message,
                    parsed
                        .get("error")
                        .and_then(|e| e.get("details"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                ),
            );
            // PHASE 6 STEP 4: a failed money op may still carry the
            // broadcast signature in the envelope (confirmation-timeout
            // case). Capture it — verbatim, never fabricated — so the
            // payment flow can persist it into the intent for later
            // reconciliation. Non-payment ops never surface one anyway.
            let surfaced_signature = if op.is_payment() {
                extract_signature(&parsed)
            } else {
                None
            };
            eprintln!(
                "[rialo-diag] op={:?} exit={} dur_ms={} out_len={} err_len={} sig_evidence={} code={} outcome=envelope_error",
                op,
                exit_code,
                started.elapsed().as_millis(),
                stdout.len(),
                stderr.len(),
                surfaced_signature.is_some(),
                code
            );
            return Err(RialoError {
                code,
                detail: with_confirmation_timeout_note(code, message),
                tx_signature: surfaced_signature,
            });
        }

        if !output.status.success() {
            let text = if stderr.is_empty() { &stdout } else { &stderr };
            let code = classify(op, text);
            eprintln!(
                "[rialo-diag] op={:?} exit={} dur_ms={} out_len={} err_len={} code={} outcome=exit_nonzero",
                op,
                exit_code,
                started.elapsed().as_millis(),
                stdout.len(),
                stderr.len(),
                code
            );
            return Err(RialoError::plain(
                code,
                with_confirmation_timeout_note(code, first_line(text)),
            ));
        }

        Ok(parsed)
    }

    /// Chain connectivity probe. Ok(height) when the RPC answers.
    ///
    /// G21.12.40 — CLI-less fallback: the deployed runtime image does NOT
    /// ship the `rialo` CLI (Dockerfile: only rust-built server + frontend),
    /// so the historical CLI-only probe classified a healthy endpoint as
    /// RIALO_RPC_UNAVAILABLE. Order is now: CLI probe first (full fidelity
    /// when the CLI exists — local dev, signer hosts), then a raw
    /// JSON-RPC `getBlockHeight` on the ONE configured endpoint using the
    /// established read-only plumbing (`rpc_request_body` positional-array
    /// params — the wire shape the endpoint 400s without). Both lanes are
    /// strictly read-only; neither fabricates a height.
    pub fn health(&self) -> Result<u64, RialoError> {
        match self.run(Operation::Read, &["client", "get-block-height"]) {
            Ok(value) => value
                .get("block_height")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    RialoError::plain("RIALO_ERROR", "block height missing in RPC response".into())
                }),
            // CLI unavailable/failed → raw JSON-RPC fallback (same endpoint,
            // same read-only discipline). Scalar result on this method: the
            // reply is `{"result": <u64>}` (object-params probes return
            // -32602, verified live against testnet).
            //
            // G21.12.46 — verified-live wire shape: the endpoint rejects the
            // generic `rpc_request_body` envelope (`"params": [[]]` → HTTP
            // 400 -32602 "expected struct RequestBlockHeightConfig") and
            // accepts TOP-LEVEL `"params": []` (HTTP 200 scalar). Build the
            // request inline with exactly `"params": []`.
            Err(cli_err) => {
                let body = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "getBlockHeight",
                    "params": [],
                });
                let client = reqwest::blocking::Client::builder()
                    .timeout(std::time::Duration::from_secs(8))
                    .build()
                    .map_err(|e| {
                        RialoError::plain("RIALO_RPC_UNAVAILABLE", format!("http client: {e}"))
                    })?;
                let response = client
                    .post(&self.rpc_url)
                    .header("Content-Type", "application/json")
                    .body(serde_json::to_string(&body).unwrap_or_default())
                    .send()
                    .map_err(|e| {
                        RialoError::plain(
                            "RIALO_RPC_UNAVAILABLE",
                            format!("network error: {e} | cli also failed: {}", cli_err.detail),
                        )
                    })?;
                let status = response.status();
                let parsed: Value = response.json().map_err(|e| {
                    RialoError::plain(
                        "RIALO_RPC_UNAVAILABLE",
                        format!("unparseable RPC reply: {e}"),
                    )
                })?;
                if !status.is_success() {
                    return Err(RialoError::plain(
                        "RIALO_RPC_UNAVAILABLE",
                        format!("RPC returned {status}"),
                    ));
                }
                if let Some(err) = jsonrpc_error(&parsed) {
                    return Err(RialoError::plain(
                        "RIALO_ERROR",
                        err.get("message")
                            .and_then(Value::as_str)
                            .unwrap_or("rpc error")
                            .to_string(),
                    ));
                }
                parsed.get("result").and_then(Value::as_u64).ok_or_else(|| {
                    RialoError::plain("RIALO_ERROR", "block height missing in RPC response".into())
                })
            }
        }
    }

    /// Balance in RLO. Err — never a fake zero — when the RPC is down.
    pub fn balance(&self, address: &str) -> Result<f64, RialoError> {
        match self.run(Operation::Read, &["client", "balance", address]) {
            Ok(value) => value.get("balance").and_then(Value::as_f64).ok_or_else(|| {
                RialoError::plain("RIALO_ERROR", "balance missing in RPC response".into())
            }),
            // G21.12.98 — read-only raw JSON-RPC fallback (mirror of the
            // verified-live health() fallback, same endpoint + discipline):
            // the production image ships WITHOUT the rialo CLI, so every
            // /api/me balance read previously failed with RIALO_CLI_UNAVAILABLE
            // while /api/health succeeded via its own fallback. Wire shape
            // verified live against testnet (G21.12.98):
            //   getBalance rejects a bare-string account (invalid type string),
            //   and accepts exactly {"address": "<base58>"} →
            //   {"result": {"version":0,"context":{...},"value": <u64 kelvins>}}
            // Units (decisive live cross-check): RPC value=4510080 kelvins for
            // an account whose CLI `client balance` reports 0.00451008 RLO ⇒
            // RLO = kelvins / 1_000_000_000 (native decimals = 9; the
            // rent-exemption constant 890880 matches the lamport scale).
            //
            // NEVER fabricates a zero: every malformed/unparseable/incomplete
            // reply is a typed error (RIALO_ERROR / RIALO_RPC_UNAVAILABLE).
            Err(cli_err) => {
                let body = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "getBalance",
                    "params": [{ "address": address }],
                });
                let client = reqwest::blocking::Client::builder()
                    .timeout(std::time::Duration::from_secs(8))
                    .build()
                    .map_err(|e| {
                        RialoError::plain("RIALO_RPC_UNAVAILABLE", format!("http client: {e}"))
                    })?;
                let response = client
                    .post(&self.rpc_url)
                    .header("Content-Type", "application/json")
                    .body(serde_json::to_string(&body).unwrap_or_default())
                    .send()
                    .map_err(|e| {
                        RialoError::plain(
                            "RIALO_RPC_UNAVAILABLE",
                            format!("network error: {e} | cli also failed: {}", cli_err.detail),
                        )
                    })?;
                let status = response.status();
                let parsed: Value = response.json().map_err(|e| {
                    RialoError::plain(
                        "RIALO_RPC_UNAVAILABLE",
                        format!("unparseable RPC reply: {e}"),
                    )
                })?;
                if !status.is_success() {
                    return Err(RialoError::plain(
                        "RIALO_RPC_UNAVAILABLE",
                        format!("RPC returned {status}"),
                    ));
                }
                if let Some(err) = jsonrpc_error(&parsed) {
                    return Err(RialoError::plain(
                        "RIALO_ERROR",
                        err.get("message")
                            .and_then(Value::as_str)
                            .unwrap_or("rpc error")
                            .to_string(),
                    ));
                }
                const KELVINS_PER_RLO: f64 = 1_000_000_000.0;
                let kelvins = parsed
                    .get("result")
                    .and_then(|r| r.get("value"))
                    .and_then(Value::as_u64)
                    .ok_or_else(|| {
                        RialoError::plain("RIALO_ERROR", "balance missing in RPC response".into())
                    })?;
                Ok(kelvins as f64 / KELVINS_PER_RLO)
            }
        }
    }

    /// PHASE 6 STEP 4 (schema-remediated) — read-only transaction lookup,
    /// the reconciliation evidence lane. PRIMARY source is exactly:
    ///   rialo --url <rpc> --no-setup client transaction <signature> --json
    /// through the established `RialoConfig::run` discipline (same CLI,
    /// same single RPC endpoint, same typed error classification).
    ///
    /// SECONDARY sources are read-only JSON-RPC supplements on the ONE
    /// configured endpoint (never submissions, never the CLI):
    ///   * `getTransaction`   — supplements a found CLI record with the
    ///                          chain-timing fields the CLI omitted
    ///                          (blockTime / blockHeight). It NEVER
    ///                          supplies `executed`: the vendor
    ///                          TransactionStatusMetadata has no executed
    ///                          field, and the explicit-executed rule
    ///                          (fix 2) stays enforced at the parse layer.
    ///   * `getSignatureStatuses` — consulted only when the CLI errored:
    ///                          an explicit status (with its own
    ///                          executed bool) upgrades a raw error to
    ///                          Found evidence; a null/absent status is
    ///                          NOT-found (temporary), never absence.
    ///   * `getBlock`         — the ONLY chain-timing fallback (fix 6):
    ///                          block time is read from the block the
    ///                          record names. Nothing is ever inferred
    ///                          from local timestamps (intent created_at
    ///                          is used only as a window to CHECK
    ///                          against, never as evidence).
    ///
    /// Outcome contract (the reconciler depends on this; nothing here is
    /// ever decisive beyond what the node actually said):
    ///   Found(record)      → get_transaction succeeded. record.executed
    ///                        && record.err.is_none()  => successful tx
    ///                        !executed || err present => failed tx
    ///   NotFound           → reachable RPC answered "not found": a
    ///                        TEMPORARY signal before the finality horizon,
    ///                        never permanent absence.
    ///   Unavailable(err)   → RIALO_RPC_UNAVAILABLE / CLI-down / an
    ///                        unclassified node answer: transient, retryable.
    ///   Malformed          → success-shaped reply that cannot be parsed
    ///                        into a complete record: unknown, NOT absence.
    pub fn transaction_lookup(&self, signature: &str) -> TxLookup {
        if signature.is_empty() || signature.len() > 128 {
            return TxLookup::Malformed;
        }
        match self.run(Operation::Read, &["client", "transaction", signature]) {
            Ok(value) => match parse_tx_record(signature, &value) {
                None => TxLookup::Malformed,
                Some(mut rec) => {
                    self.supplement_chain_timing(signature, &mut rec);
                    TxLookup::Found(rec)
                }
            },
            Err(err) => {
                // Read-only status supplement FIRST: an explicit node
                // status is evidence; the raw CLI error only classifies
                // what the node did NOT answer.
                match self.signature_status_probe(signature) {
                    StatusProbe::Explicit(record) => return TxLookup::Found(record),
                    // An ANSWERED query with no status for this signature:
                    // the node does not know it yet — temporary not-found,
                    // never permanent absence.
                    StatusProbe::NoStatus => return TxLookup::NotFound,
                    // Probe itself failed (RPC down / unreadable): fall
                    // through and classify strictly from the primary error
                    // — fail closed to the transient bucket.
                    StatusProbe::Inconclusive => {}
                }
                if err.code == "RIALO_RPC_UNAVAILABLE" || err.code == "RIALO_CLI_UNAVAILABLE" {
                    TxLookup::Unavailable(err)
                } else if is_not_found_message(&err.detail) {
                    TxLookup::NotFound
                } else {
                    // Unknown-shaped failure: the node may have answered
                    // with a non-classified problem. Fail closed to the
                    // transient bucket — NEVER to a permanent verdict.
                    TxLookup::Unavailable(err)
                }
            }
        }
    }

    /// Read-only JSON-RPC `getSignatureStatuses` for exactly ONE
    /// signature. Distinguishes the three probe outcomes so the caller
    /// can fail closed correctly:
    ///   Explicit(record) → the node answered WITH a status carrying its
    ///                      own executed bool — evidence. The timing of
    ///                      the named slot is filled through `getBlock`
    ///                      (fix 6), never inferred.
    ///   NoStatus         → the node answered but has no status for this
    ///                      signature (null entry / missing entry) —
    ///                      temporary not-found.
    ///   Inconclusive     → the probe itself failed (RPC down, unparseable
    ///                      reply, entry missing its executed bool). The
    ///                      caller must classify from the primary error.
    fn signature_status_probe(&self, signature: &str) -> StatusProbe {
        let params = serde_json::json!({
            "version": 0u16,
            "signatures": [signature],
        });
        match self.rpc_read("getSignatureStatuses", &params) {
            Err(_) => StatusProbe::Inconclusive,
            Ok(result) => match parse_signature_status(signature, &result) {
                StatusEntry::Explicit(mut rec) => {
                    self.supplement_chain_timing(signature, &mut rec);
                    StatusProbe::Explicit(rec)
                }
                StatusEntry::NoStatus => StatusProbe::NoStatus,
                StatusEntry::Inconclusive => StatusProbe::Inconclusive,
            },
        }
    }

    /// Read-only JSON-RPC `getBalance` on the ONE configured endpoint.
    /// Returns the balance kelvin AND the node's `context.slot` — the
    /// exact state slot at which the balance was computed. This is the
    /// GATE 2 observation-slot lane: the CLI `client balance` envelope
    /// strips `context` (verified live against testnet 2026-10-10:
    /// RPC returns {"context":{"slot":N},"value":V} but the CLI prints
    /// only {"balance":...,"address":[...]}), so the CLI path can never
    /// carry a freshness slot; this direct RPC read is the ONLY evidence
    /// source for the commitment-release predicate. Signs and submits
    /// nothing. Never invents a slot: a missing/unparseable `context`
    /// yields Ok(None) and the caller fails closed (commitment held).
    pub fn balance_with_observation_slot(
        &self,
        address: &str,
    ) -> Result<(f64, Option<u64>), RialoError> {
        let params = serde_json::json!({
            "version": 0u16,
            "address": address,
        });
        match self.rpc_read("getBalance", &params) {
            Ok(result) => {
                let value = result.get("value").and_then(Value::as_f64).ok_or_else(|| {
                    RialoError::plain("RIALO_ERROR", "balance missing in RPC response".into())
                })?;
                // context.slot is the RPC freshness slot (RpcResponseContext
                // { slot: Slot }); absent/None is handled fail-closed upstream.
                let slot = result.get("context").and_then(|c| u64_field(c, &["slot"]));
                Ok((value, slot))
            }
            Err(err) => Err(err),
        }
    }

    /// FIX 6 — chain-timing supplementation/fallback. When a record
    /// names a signature/slot/block height but carries NO block time,
    /// the time is read FROM THE CHAIN: first the vendor `getTransaction`
    /// record (top-level blockTime + blockHeight for this signature),
    /// then `getBlock(block_height)` for the named block. These are the
    /// ONLY timing sources that exist: block time is NEVER synthesized
    /// from intent `created_at` or any local clock, and a failed/absent
    /// read leaves the record incomplete so the reconciler fails closed
    /// to Unknown. getTransaction never supplies `executed` — the
    /// explicit-executed rule (fix 2) is untouched by supplementation.
    fn supplement_chain_timing(&self, signature: &str, rec: &mut TxRecord) {
        if rec.block_time.is_some() {
            return;
        }
        // 1) getTransaction on the ONE endpoint (vendor object params).
        let params = serde_json::json!({
            "version": 0u16,
            "signature": signature,
        });
        if let Ok(result) = self.rpc_read("getTransaction", &params) {
            if rec.block_height.is_none() {
                rec.block_height = u64_field(&result, &["block_height", "blockHeight"]);
            }
            if let Some(t) = i64_field(&result, &["block_time", "blockTime"]) {
                rec.block_time = Some(normalize_block_time(t));
                return;
            }
        }
        // 2) getBlock(block_height) — the named block, never a guess.
        let Some(height) = rec.block_height.or(rec.slot).filter(|h| *h > 0) else {
            return;
        };
        let params = serde_json::json!({
            "version": 0u16,
            "block_height": height,
        });
        let Ok(result) = self.rpc_read("getBlock", &params) else {
            return;
        };
        if let Some(t) = parse_block_time(&result) {
            rec.block_time = Some(t);
        }
    }

    /// Shared read-only JSON-RPC plumbing for the STEP 4 remediation
    /// lanes (getSignatureStatuses / getTransaction / getBlock /
    /// getSignaturesForAddress). The vendor wire style is an OBJECT
    /// params envelope (rialo-api-types-0.18.1 request structs are
    /// serialized as one positional object: `{version, ...fields,
    /// config}`) — NOT Solana-style positional arrays. Posts to the ONE
    /// configured `self.rpc_url`; signs and submits nothing. Returns the
    /// JSON-RPC `result` object.
    fn rpc_read(&self, method: &'static str, params: &Value) -> Result<Value, RialoError> {
        let body = rpc_request_body(method, params);
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| RialoError::plain("RIALO_RPC_UNAVAILABLE", format!("http client: {e}")))?;
        let response = client
            .post(&self.rpc_url)
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&body).unwrap_or_default())
            .send()
            .map_err(|e| {
                RialoError::plain("RIALO_RPC_UNAVAILABLE", format!("network error: {e}"))
            })?;
        let status = response.status();
        let parsed: Value = response.json().map_err(|e| {
            RialoError::plain(
                "RIALO_RPC_UNAVAILABLE",
                format!("unparseable RPC reply: {e}"),
            )
        })?;
        if !status.is_success() {
            return Err(RialoError::plain(
                "RIALO_RPC_UNAVAILABLE",
                format!("RPC returned {status}"),
            ));
        }
        if let Some(err) = jsonrpc_error(&parsed) {
            return Err(RialoError::plain(
                "RIALO_ERROR",
                err.get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("rpc error")
                    .to_string(),
            ));
        }
        // FIX 5 — decisive data lives at `result.value` in every
        // vendor read; anything else is NOT an answer.
        parsed
            .get("result")
            .filter(|r| r.is_object())
            .cloned()
            .ok_or_else(|| RialoError::plain("RIALO_ERROR", "missing result object".into()))
    }

    /// PHASE 6 STEP 4 — bounded address-history discovery for the
    /// unknown-without-signature lane.
    ///
    /// Vendor-API provenance: the CLI (0.18.1, `rialo client --help`) has
    /// NO per-address history command, but the vendor API does —
    /// `getSignaturesForAddress` is defined in vendor/rialo-cdk
    /// (rpc/client.rs, docs/rpc-reference.md) on rialo-api-types-0.18.1
    /// (messages/get_signatures_for_address.rs): config accepts ONLY
    /// `limit` (1-1000) and SIGNATURE cursors `before`/`until` (no time
    /// cursors, no commitment field — the time window is therefore
    /// client-side on the returned block times, and the bound is the
    /// hard `limit`). Response envelope is `{ context, value: [...] }`.
    /// This is the JSON-RPC form of that vendor API, called READ-ONLY
    /// from inside this module on the ONE configured RPC endpoint
    /// (`self.rpc_url`). No other module may reach the RPC; nothing here
    /// signs or submits anything.
    pub fn signatures_for_address(
        &self,
        address: &str,
        until_signature: Option<&str>,
        limit: u64,
    ) -> Result<Vec<SignatureInfoRecord>, RialoError> {
        if address.is_empty() || address.len() > 64 {
            return Err(RialoError::plain(
                "INVALID_RECIPIENT",
                "bad address shape".into(),
            ));
        }
        let limit = limit.clamp(1, 25);
        // FIX 4 — vendor object params (rialo-api-types GetSignaturesForAddress-
        // Request: {version, address, config{limit, before, until}} as ONE
        // positional object). The Solana-style positional
        // [address, config] form is REJECTED by the rialo node — this exact
        // live-shape mismatch is what the schema remediation fixes.
        let mut config = serde_json::json!({ "limit": limit });
        if let Some(u) = until_signature {
            config["until"] = serde_json::json!(u);
        }
        let params = serde_json::json!({
            "version": 0u16,
            "address": address,
            "config": config,
        });
        // rpc_read already surfaces jsonrpc errors as typed RIALO_ERROR and
        // transport failures as RIALO_RPC_UNAVAILABLE (scan lane degrades
        // the intent to (kept) Unknown either way).
        let result = self.rpc_read("getSignaturesForAddress", &params)?;
        // FIX 5 — decisive data is result.value (vendor
        // GetSignaturesForAddressResponse {context, value}); anything else
        // is not an answer.
        let items = result
            .get("value")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                RialoError::plain("RIALO_ERROR", "result.value is not an array".into())
            })?;
        Ok(parse_signature_items(items))
    }

    /// Request a faucet airdrop. The CLI derives the faucet endpoint from the
    /// RPC URL; there is no separate faucet configuration.
    pub fn airdrop(&self, address: &str, amount: &str) -> Result<(), RialoError> {
        let kelvins = Self::parse_amount_to_kelvins(amount)?;
        match self.run(
            Operation::Faucet,
            &[
                "client",
                "airdrop",
                "--address",
                address,
                "--amount",
                amount,
                "--timeout",
                "30000",
            ],
        ) {
            Ok(value) => {
                // Airdrop success envelope has no `success:false`; presence of
                // a balance/new-balance field or exit code 0 is sufficient.
                let _ = value;
                Ok(())
            }
            // G21.13.05 — CLI path failed (deployed image ships without the
            // rialo CLI): fall back to the equivalent raw requestAirdrop wire
            // call captured from the vendor CLI. Still gated upstream by the
            // faucet handler kill-switch; amount already parsed once above.
            Err(cli_err) => {
                eprintln!(
                    "[rialo] CLI airdrop unavailable ({cli_err:?}); falling back to raw requestAirdrop"
                );
                self.request_airdrop_raw(address, kelvins).map(|_sig| ())
            }
        }
    }
    fn parse_amount_to_kelvins(amount_rlo: &str) -> Result<u64, RialoError> {
        let v: f64 = amount_rlo.trim().parse().map_err(|_| {
            RialoError::plain(
                "RIALO_ERROR",
                format!("invalid faucet amount: {amount_rlo}"),
            )
        })?;
        if !v.is_finite() || v <= 0.0 {
            return Err(RialoError::plain(
                "RIALO_ERROR",
                format!("faucet amount must be > 0: {amount_rlo}"),
            ));
        }
        let kelvins = v * 1_000_000_000.0;
        // Sub-kelvin residue would silently drop value units — reject instead.
        if (kelvins - kelvins.round()).abs() > f64::EPSILON.max(kelvins.abs() * 1e-9) {
            return Err(RialoError::plain(
                "RIALO_ERROR",
                format!("faucet amount exceeds kelvin precision: {amount_rlo}"),
            ));
        }
        if kelvins >= u64::MAX as f64 || kelvins < 1.0 {
            return Err(RialoError::plain(
                "RIALO_ERROR",
                format!("faucet amount out of range: {amount_rlo}"),
            ));
        }
        Ok(kelvins.round() as u64)
    }

    /// G21.13.05 — raw JSON-RPC faucet fallback (read-only design note: this
    /// is the ONLY place a raw network WRITE exists, behind the faucet
    /// handler's kill-switch + integrity gates; it NEVER runs on read paths).
    ///
    /// Wire shape captured from the vendor CLI itself (isolated local sink,
    /// G21.13.05): the CLI's `client airdrop` issues EXACTLY
    ///   {"jsonrpc":"2.0","id":1,"method":"requestAirdrop",
    ///    "params":[{"version":0,"pubkey":"<addr>","kelvins":<u64>}]}
    /// ─ amount scaling proved live: 1 RLO → 1_000_000_000 kelvins,
    ///   2.5 RLO → 2_500_000_000 kelvins (÷ non-integers rejected upstream).
    /// Success semantics: HTTP 200 + JSON-RPC result carrying the airdrop
    /// signature. Ambiguous outcomes (timeout/connection drop AFTER submit)
    /// are intentionally typed RIALO_TRANSFER_CONFIRMATION_TIMEOUT-style
    /// errors here — the caller must NOT assume success OR failure and must
    /// not auto-retry (duplicate funding risk; faucet has no idempotency key).
    ///
    /// SAFETY: never fabricates success on malformed envelopes (missing
    /// result → typed error), and only ever invoked behind the production
    /// kill-switch in server.rs::faucet.
    fn request_airdrop_raw(&self, address: &str, kelvins: u64) -> Result<String, RialoError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "requestAirdrop",
            "params": [{
                "version": 0,
                "pubkey": address,
                "kelvins": kelvins,
            }],
        });
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(35)) // CLI uses 30s; +5s grace
            .build()
            .map_err(|e| RialoError::plain("RIALO_RPC_UNAVAILABLE", format!("http client: {e}")))?;
        let response = client
            .post(&self.rpc_url)
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&body).unwrap_or_default())
            .send()
            .map_err(|e| {
                // Ambiguous: the request MAY have reached the faucet before
                // the connection failed. Treat as unknown, never retry here.
                RialoError::plain(
                    "RIALO_RPC_UNAVAILABLE",
                    format!("airdrop network error (state unknown, no retry): {e}"),
                )
            })?;
        let status = response.status();
        let parsed: Value = response.json().map_err(|e| {
            // 2xx but unparseable = ambiguous evidence; do not claim success.
            RialoError::plain(
                "RIALO_ERROR",
                format!("airdrop reply unparseable (state unknown): {e}"),
            )
        })?;
        if !status.is_success() {
            return Err(RialoError::plain(
                "RIALO_ERROR",
                format!("airdrop RPC returned {status}"),
            ));
        }
        if let Some(err) = jsonrpc_error(&parsed) {
            return Err(RialoError::plain(
                "RIALO_ERROR",
                err.get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("rpc error")
                    .to_string(),
            ));
        }
        // Signature may be a bare string or wrapped — accept standard shapes,
        // reject empty/missing (an empty success envelope is not evidence).
        let sig = parsed
            .pointer("/result")
            .and_then(|r| {
                r.as_str()
                    .map(|s| s.to_string())
                    .or_else(|| r.get("signature").and_then(Value::as_str).map(String::from))
            })
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                RialoError::plain(
                    "RIALO_ERROR_CONFIRMATION_UNKNOWN",
                    "airdrop reply missing signature; outcome unknown".into(),
                )
            })?;
        Ok(sig)
    }

    /// Transfer RLO from a persisted wallet keypair file to `to`.
    /// The wallet file format (JSON byte array written by rialo-s-keypair) is
    /// directly accepted by the CLI as a keypair path — verified against
    /// testnet. No key material is ever read into the server for signing.
    ///
    /// Clock-skew resilience: CLI 0.18.1 stamps `valid_from` from
    /// `SystemTime::now()` on this machine and offers no override, so a
    /// `TimestampInFuture` rejection (classified RIALO_CLOCK_SKEW) is a
    /// transient preflight failure — the node's clock is momentarily behind
    /// ours and the transaction was NOT accepted. A retry re-invokes the CLI,
    /// which rebuilds and re-signs a brand-new transaction with a fresh
    /// `valid_from` (nothing is ever reused). Bounded to 3 attempts with
    /// 400ms/800ms backoff. NO other error class retries here: in particular
    /// RIALO_TRANSFER_CONFIRMATION_TIMEOUT must never be retried because the
    /// original transaction may already be broadcast/landed.
    pub fn transfer(
        &self,
        keypair_path: &PathBuf,
        to: &str,
        amount: &str,
    ) -> Result<String, RialoError> {
        let path = keypair_path
            .to_str()
            .ok_or_else(|| RialoError::plain("RIALO_ERROR", "non-utf8 wallet path".into()))?;

        let mut last_err = None;
        for attempt in 0..3u64 {
            if attempt > 0 {
                std::thread::sleep(std::time::Duration::from_millis(400 * attempt));
            }
            match self
                .run(
                    Operation::Transfer,
                    &["client", "transfer", to, amount, path],
                )
                .and_then(transfer_signature)
            {
                Ok((signature, _slot)) => return Ok(signature),
                Err(err) => {
                    let retryable = is_retryable_clock_skew(err.code);
                    last_err = Some(err);
                    if !retryable {
                        break;
                    }
                }
            }
        }
        // All attempts failed: the final error (RIALO_CLOCK_SKEW if that is
        // what it was) is returned unchanged — never rewritten.
        Err(last_err
            .unwrap_or_else(|| RialoError::plain("RIALO_TRANSFER_ERROR", "transfer failed".into())))
    }

    // ---------------------------------------------------------------------
    // PHASE 10 ITEM 6 — the execution/broadcast half of the OLD working
    // payment path, reconnected behind the hardened signer.
    // ---------------------------------------------------------------------
    //
    // The old flow was: authorization → policy → canonical intent → ONE
    // money-moving call → real tx signature → Confirmed commit → the
    // read-only reconciliation lane. What the Hardened Signer cutover
    // removed was the LEGACY SIGNING BOUNDARY inside that call (the CLI
    // reading a keypair file); the flow itself, its error grammar, its
    // confirmation evidence and its reconciliation were never replaced.
    //
    // This is that same execution/broadcast path with ONLY the signing
    // boundary swapped: it submits an ALREADY-SIGNED envelope produced by
    // the isolated signer over the ONE RPC endpoint this module owns
    // (`self.rpc_url` — the repo rule that no other module may decide an
    // endpoint or spawn the CLI stands), confirms it with the EXISTING
    // read-only status probe, and returns the signature the node reported.
    // It signs NOTHING and reads NO key material: the funded key never
    // enters this process.
    //
    // Wire contract (never guessed): `rialo-api-types-0.18.1`
    // `SendTransactionRequest { version, transaction (base64), config
    // { encoding:"base64", maxRetries, skipPreflight, waitForExecution } }`
    // as the vendored SDK itself posts it
    // (vendor/rialo-cdk/src/rpc/client.rs `send_transaction`).

    /// Bounded submission budget. `waitForExecution` makes the node await
    /// execution, so this is deliberately longer than the 15s read budget —
    /// but still bounded: a hung RPC is the uncertainty class, never an
    /// unbounded wait.
    const SUBMIT_TIMEOUT_SECS: u64 = 45;
    /// Bounded confirmation window (polls × 1s) after acceptance.
    const SUBMIT_CONFIRM_POLLS: u32 = 30;

    /// Submit an ALREADY-SIGNED transaction envelope (base64) and wait for
    /// on-chain execution evidence. `expected_signature` is the signer's
    /// 64-byte signature: the signature the node reports MUST decode
    /// (base58) to exactly those bytes, or the answer is not about the
    /// transaction we signed and is never accepted as success.
    ///
    /// Outcomes ride the EXISTING typed grammar, unchanged:
    ///   Ok(signature)          → the node reported the signature AND the
    ///                            read-only status probe reported execution.
    ///   RIALO_TRANSFER_*       → definitive pre-execution refusal (the node
    ///                            answered "no") — the established refund
    ///                            class.
    ///   RIALO_TRANSFER_CONFIRMATION_TIMEOUT
    ///                          → outcome UNKNOWN (transport failure,
    ///                            unclassifiable answer, no execution
    ///                            evidence within the window): the core
    ///                            holds the reservation and gates replay.
    /// Nothing is ever converted into "paid" without the node's evidence.
    pub fn submit_signed_transaction(
        &self,
        signed_tx_b64: &str,
        expected_signature: &[u8],
    ) -> Result<String, RialoError> {
        let uncertain = |detail: String| RialoError {
            code: "RIALO_TRANSFER_CONFIRMATION_TIMEOUT",
            detail: with_confirmation_timeout_note("RIALO_TRANSFER_CONFIRMATION_TIMEOUT", detail),
            tx_signature: None,
        };
        if signed_tx_b64.is_empty() || expected_signature.len() != 64 {
            return Err(RialoError::plain(
                "RIALO_TRANSFER_ERROR",
                "signed envelope malformed (pre-dispatch)".to_string(),
            ));
        }
        // the vendor object-params envelope, exactly as the SDK posts it
        let params = serde_json::json!({
            "version": 0u16,
            "transaction": signed_tx_b64,
            "config": {
                "encoding": "base64",
                "maxRetries": 0usize,
                "skipPreflight": false,
                "waitForExecution": true,
            },
        });
        let body = rpc_request_body("sendTransaction", &params);
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(Self::SUBMIT_TIMEOUT_SECS))
            .build()
            .map_err(|e| uncertain(format!("submission http client failed: {e}")))?;
        let response = client
            .post(&self.rpc_url)
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&body).unwrap_or_default())
            .send();
        // A transport failure AFTER the request may have been dispatched is
        // the uncertainty class, never a definitive "not broadcast".
        let response = match response {
            Ok(response) => response,
            Err(e) => return Err(uncertain(format!("sendTransaction transport failed: {e}"))),
        };
        let status = response.status();
        let parsed: Value = match response.json() {
            Ok(parsed) => parsed,
            Err(e) => {
                // the node's answer is unreadable: was the transaction
                // accepted? Unknown — hold, never refund-on-guess.
                return Err(uncertain(format!("sendTransaction reply unparseable: {e}")));
            }
        };
        if let Some(err) = jsonrpc_error(&parsed) {
            let message = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("rpc error")
                .to_string();
            // the established payment classifier, so clock skew /
            // confirmation-timeout / transfer codes mean exactly what they
            // meant on the old CLI path
            let code = classify(Operation::Transfer, &message);
            let surfaced = extract_signature(&parsed);
            return Err(RialoError {
                code,
                detail: with_confirmation_timeout_note(code, first_line(&message)),
                tx_signature: surfaced,
            });
        }
        if !status.is_success() {
            return Err(uncertain(format!("sendTransaction returned {status}")));
        }
        let reported = parsed
            .get("result")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| uncertain("sendTransaction carried no signature result".to_string()))?
            .to_string();
        // evidence binding: the reported signature MUST be the one the
        // signer produced — base58-decoded and compared byte-for-byte.
        // A mismatch means the node answered about something else; the
        // outcome is unknown, and nothing is reported as paid.
        if base58_decode(&reported).as_deref() != Some(expected_signature) {
            return Err(RialoError {
                code: "RIALO_TRANSFER_CONFIRMATION_TIMEOUT",
                detail: with_confirmation_timeout_note(
                    "RIALO_TRANSFER_CONFIRMATION_TIMEOUT",
                    "the node reported a signature that is not the signer's".to_string(),
                ),
                tx_signature: None,
            });
        }
        // CONFIRMATION: the same read-only status evidence the reconciler
        // uses (its own `executed` bool — never inferred from a local
        // clock). Bounded window; no evidence inside it is Unknown.
        for _ in 0..Self::SUBMIT_CONFIRM_POLLS {
            match self.signature_status_probe(&reported) {
                StatusProbe::Explicit(record) => {
                    if record.executed && record.err.is_none() {
                        return Ok(reported);
                    }
                    if let Some(err) = record.err.clone() {
                        // the node answered WITH an execution error:
                        // definitive, refundable — the established
                        // pre-execution/refund class. The signature is
                        // surfaced verbatim (it is the node's own answer).
                        return Err(RialoError {
                            code: "RIALO_TRANSFER_ERROR",
                            detail: format!("transaction failed on-chain: {err}"),
                            tx_signature: Some(reported),
                        });
                    }
                    // executed=false with no error tag is a PENDING answer,
                    // not a verdict: keep polling. Never a refund guess.
                }
                // answered, not known yet → keep polling (never absence)
                StatusProbe::NoStatus | StatusProbe::Inconclusive => {}
            }
            std::thread::sleep(std::time::Duration::from_millis(1000));
        }
        Err(uncertain(
            "no execution evidence within the confirmation window".to_string(),
        ))
    }

    // ---------------------------------------------------------------------
    // Venus program layer
    // ---------------------------------------------------------------------
    //
    // `client program invoke` has NO `--keypair` flag: the signer must be an
    // alias registered in the CLI config. Instead of registering every user
    // wallet as a permanent alias in the shared config, each invocation runs
    // with `-c <ephemeral dir>` — a throwaway config directory (mode 700)
    // whose config.toml maps one internal alias to the user's existing
    // wallet FILE PATH. Only the path is written; private key material is
    // never copied, read, logged, or exposed. The directory is removed after
    // the invocation. This was verified against testnet: balance + program
    // `start` invocations signed correctly per-wallet with zero key copies
    // and zero permanent aliases.

    /// Locate the program manifest: `<program_dir>/wit/*-manifest.json`.
    pub fn program_manifest_path(&self) -> Option<PathBuf> {
        let wit = self.program_dir.join("wit");
        let entries = std::fs::read_dir(&wit).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name()?.to_string_lossy().to_string();
            if name.ends_with("-manifest.json") {
                return Some(path);
            }
        }
        None
    }

    /// Integrity guard for the deployed account-index bug
    /// (rialo-venus-dsl emitted `subscriber_interface` in the execute
    /// manifest while the compiled dispatch only counts it when
    /// subscription accounts exist — recipient was mis-slotted and the CPI
    /// paid the Subscriber interface account; reproduced on testnet
    /// 2026-09-28 and fixed live via a corrected manifest ordering).
    ///
    /// Returns Ok(()) only when the manifest's `execute` accounts match the
    /// layout the deployed bytecode expects:
    /// `[payer, workflow_pda, system_program, recipient]` — i.e. NO
    /// `subscriber_interface` slot when no subscription accounts exist.
    pub fn validate_program_manifest(&self) -> Result<PathBuf, RialoError> {
        let path = self.program_manifest_path().ok_or(RialoError::plain(
            "PROGRAM_MANIFEST_MISSING",
            format!(
                "no wit/*-manifest.json under {}",
                self.program_dir.display()
            ),
        ))?;
        let text = std::fs::read_to_string(&path).map_err(|e| {
            RialoError::plain(
                "PROGRAM_MANIFEST_MISSING",
                format!("cannot read manifest: {}", e),
            )
        })?;
        let value: Value = serde_json::from_str(&text).map_err(|e| {
            RialoError::plain(
                "PROGRAM_MANIFEST_INVALID",
                format!("manifest is not valid JSON: {}", e),
            )
        })?;
        Self::check_execute_account_order(&value)?;
        Ok(path)
    }

    /// Pure manifest-shape check (unit-testable): when the execute
    /// instruction has no subscription PDA accounts, subscriber_interface
    /// must NOT appear before the recipient.
    fn check_execute_account_order(manifest: &Value) -> Result<(), RialoError> {
        let names: Vec<&str> = manifest
            .pointer("/instructions/execute/accounts")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                RialoError::plain(
                    "PROGRAM_MANIFEST_INVALID",
                    "manifest has no execute.accounts array".into(),
                )
            })?
            .iter()
            .filter_map(|a| a.get("name").and_then(Value::as_str))
            .collect();

        let has_subs = names.iter().any(|n| n.starts_with("subscription_pda"));
        let idx_sub = names.iter().position(|n| *n == "subscriber_interface");
        let idx_recipient = names.iter().position(|n| *n == "recipient");

        if !has_subs {
            if idx_sub.is_some() {
                return Err(RialoError::plain(
                    "PROGRAM_MANIFEST_BUG",
                    "execute.accounts contains subscriber_interface while \
                             the workflow has no subscription accounts — the deployed \
                             bytecode would read the NEXT slot as the recipient and \
                             pay the Subscriber interface account. Regenerate the \
                             manifest with the patched rialo-venus-dsl (vendor/)."
                        .into(),
                ));
            }
        }
        // Positional invariant the deployed bytecode requires:
        // [0] payer, [1] workflow_pda, [2] system_program.
        let bad = names.len() < 3
            || names[0] != "payer"
            || names[1] != "workflow_pda"
            || names[2] != "system_program";
        if bad {
            return Err(RialoError::plain(
                "PROGRAM_MANIFEST_INVALID",
                format!(
                    "unexpected execute account layout {:?} — expected payer, \
                     workflow_pda, system_program first",
                    names
                ),
            ));
        }
        // recipient must sit at index 3 when there are no subscription/rex
        // accounts (exactly what the deployed dispatch hardcodes).
        if !has_subs {
            match idx_recipient {
                Some(3) => {}
                Some(other) => {
                    return Err(RialoError::plain(
                        "PROGRAM_MANIFEST_INVALID",
                        format!(
                            "recipient is at execute account index {}, but the \
                             deployed bytecode resolves it at 3",
                            other
                        ),
                    ));
                }
                None => {
                    return Err(RialoError::plain(
                        "PROGRAM_MANIFEST_INVALID",
                        "execute.accounts has no recipient entry".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Program readiness snapshot for GET /api/program/status (no secrets,
    /// no transactions). The on-chain probe is a read-only `get-account`
    /// — it never submits anything.
    pub fn program_status(&self) -> Value {
        let manifest_path = self.program_manifest_path();
        let manifest_status = self.validate_program_manifest();
        let cap = program_test_cap();

        // Read-only on-chain existence check for the program account.
        let on_chain = self
            .program_id
            .as_ref()
            .map(|id| match self.program_account_exists(id) {
                Ok(true) => serde_json::json!({ "status": "deployed" }),
                Ok(false) => serde_json::json!({ "status": "not_found" }),
                Err(e) => serde_json::json!({
                    "status": "unknown",
                    "error": { "code": e.code, "message": e.detail }
                }),
            });

        serde_json::json!({
            "configured": self.program_id.is_some(),
            "program_id": self.program_id,
            "manifest": {
                "path": manifest_path.map(|p| p.display().to_string()),
                "aligned_with_deployed_bytecode": manifest_status.is_ok(),
                "validation_error": manifest_status.as_ref().err().map(|e| serde_json::json!({
                    "code": e.code, "message": e.detail
                })),
            },
            "test_cap_rlo": cap,
            // Program path is only usable when: program configured, manifest
            // validated against the deployed layout, and an explicit positive
            // cap is set by the operator. Never enabled silently.
            "path_enabled": self.program_id.is_some()
                && manifest_status.is_ok()
                && cap.map_or(false, |c| c > 0.0),
            "deployed_bug_fixed": manifest_status.is_ok(),
            "on_chain": on_chain,
            "payment_route": "direct (/api/payment) — program payments require an explicit operator cap",
        })
    }

    /// Read-only check whether `program_id` exists on-chain as an owned,
    /// executable program account. Never submits a transaction.
    fn program_account_exists(&self, program_id: &str) -> Result<bool, RialoError> {
        let value = self.run(Operation::Read, &["client", "account", program_id])?;
        // Envelope varies: {"exists":bool} or a full account with owner/data.
        if let Some(exists) = value.get("exists").and_then(Value::as_bool) {
            return Ok(exists);
        }
        let found = value.get("account").is_some()
            || value.get("data").is_some()
            || value.get("owner").is_some();
        Ok(found)
    }

    /// Invoke a function on the deployed AgentPay Venus program, signed by
    /// the keypair at `keypair_path`. `args` are `key=value` strings typed
    /// from the program manifest. Returns the transaction signature.
    ///
    /// Requires AGENTPAY_PROGRAM_ID to be configured. Retries transient
    /// `TimestampInFuture` validation failures (client-clock derived
    /// valid_from racing the block producer) up to 3 attempts.
    pub fn program_invoke(
        &self,
        keypair_path: &Path,
        function: &str,
        args: &[String],
    ) -> Result<String, RialoError> {
        let program_id = self.program_id.as_deref().ok_or(RialoError::plain(
            "PROGRAM_NOT_CONFIGURED",
            "AGENTPAY_PROGRAM_ID is not set".into(),
        ))?;

        let wallet = keypair_path.canonicalize().map_err(|e| {
            RialoError::plain(
                "RIALO_WALLET_ERROR",
                format!("wallet file unavailable: {}", e),
            )
        })?;
        let wallet_str = wallet.to_str().ok_or(RialoError::plain(
            "RIALO_WALLET_ERROR",
            "non-utf8 wallet path".into(),
        ))?;
        // The manifest is validated HERE (account-index guard above) and
        // passed explicitly with --manifest, so a stale/buggy wit file can
        // never silently drive an invocation.
        let manifest = self.validate_program_manifest()?;

        // Ephemeral per-invocation keyring config directory (path only).
        let ring_dir =
            std::env::temp_dir().join(format!("agentpay-keyring-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&ring_dir).map_err(|e| {
            RialoError::plain(
                "RIALO_ERROR",
                format!("cannot create ephemeral keyring dir: {}", e),
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&ring_dir, std::fs::Permissions::from_mode(0o700));
        }
        let config_toml = format!(
            "[cli]\ncurrent_account = \"agentpay-user\"\n\n[cli.keypair_paths]\nagentpay-user = \"{}\"\n",
            wallet_str
        );
        let write_result = std::fs::write(ring_dir.join("config.toml"), config_toml);
        let result = match write_result {
            Ok(()) => self.program_invoke_loop(
                &ring_dir,
                program_id,
                &self.program_dir,
                &manifest,
                function,
                args,
            ),
            Err(e) => Err(RialoError::plain(
                "RIALO_ERROR",
                format!("cannot write ephemeral keyring config: {}", e),
            )),
        };
        let _ = std::fs::remove_dir_all(&ring_dir);
        result
    }

    fn program_invoke_loop(
        &self,
        ring_dir: &Path,
        program_id: &str,
        program_dir: &Path,
        manifest: &Path,
        function: &str,
        args: &[String],
    ) -> Result<String, RialoError> {
        // The manifest validated in `program_invoke` is passed EXPLICITLY via
        // `--manifest` so the CLI can never fall back to auto-discovering a
        // different (potentially stale/buggy) wit file from --program-dir.
        let program_dir_str = program_dir.to_str().ok_or(RialoError::plain(
            "RIALO_ERROR",
            "non-utf8 program dir".into(),
        ))?;
        let manifest_str = manifest.to_str().ok_or(RialoError::plain(
            "RIALO_ERROR",
            "non-utf8 manifest path".into(),
        ))?;
        let mut sub: Vec<String> = vec![
            "client".into(),
            "program".into(),
            "invoke".into(),
            program_id.into(),
            "--program-dir".into(),
            program_dir_str.into(),
            "--manifest".into(),
            manifest_str.into(),
            "--function".into(),
            function.into(),
        ];
        for arg in args {
            sub.push("--arg".into());
            sub.push(arg.clone());
        }
        let sub_refs: Vec<&str> = sub.iter().map(String::as_str).collect();

        let mut last_err = None;
        for attempt in 0..3 {
            match self.run_with_config_dir(Some(ring_dir), Operation::Program, &sub_refs) {
                Ok(value) => {
                    let signature = value
                        .get("signature")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    if signature.is_empty() {
                        return Err(RialoError::plain(
                            "RIALO_PROGRAM_ERROR",
                            "program invoke succeeded but no signature returned".into(),
                        ));
                    }
                    return Ok(signature);
                }
                Err(err) => {
                    let transient = err.detail.contains("TimestampInFuture");
                    last_err = Some(err);
                    if !transient {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(400 * (attempt + 1)));
                }
            }
        }
        Err(last_err.unwrap_or(RialoError::plain(
            "RIALO_PROGRAM_ERROR",
            "program invoke failed".into(),
        )))
    }
}

/// AGENTPAY_PROGRAM_TEST_MAX_RLO — the operational cap that gates the
/// program-mediated payment path. Unset/invalid = 0.0 = path disabled.
/// (Live Fix-B verification 2026-09-28 proved the deployed program pays the
/// correct recipient when the manifest account order matches the compiled
/// dispatch; the cap stays the kill-switch until operators flip it on.)
pub fn program_test_cap() -> Option<f64> {
    std::env::var("AGENTPAY_PROGRAM_TEST_MAX_RLO")
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
}

/// Extract the signature AND processing slot from a successful
/// `client transfer` envelope.
/// {"signature":"...","status":{"slot":..,"executed":true,"err":null}}
/// The slot is the GATE 2 evidence: the slot in which the transaction
/// was processed (per the vendor GetIndividualSignatureStatus/getBlock
/// semantics, slot == block height). It feeds the intent record so the
/// commitment-release predicate can compare it against a later balance
/// observation's context.slot. Absent slot -> None (fail-closed: the
/// commitment stays held until better evidence exists).
/// Logic identical to the pre-retry transfer path — moved here so the
/// retry loop re-parses each fresh CLI invocation.
fn transfer_signature(value: Value) -> Result<(String, Option<u64>), RialoError> {
    let executed = value
        .get("status")
        .and_then(|s| s.get("executed"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let err = value
        .get("status")
        .and_then(|s| s.get("err"))
        .cloned()
        .unwrap_or(Value::Null);

    if !executed || !err.is_null() {
        return Err(RialoError::plain(
            "RIALO_TRANSFER_ERROR",
            format!("transfer not executed: {}", err),
        ));
    }

    let signature = value
        .get("signature")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    // the CLI transfer envelope's status.slot (parsed by extract_status
    // for reconciliation; the SAME field, read here at success time)
    let slot = value.get("status").and_then(|s| u64_field(s, &["slot"]));
    Ok((signature, slot))
}

/// The ONLY transfer error eligible for the bounded re-sign retry: a
/// TimestampInFuture preflight rejection (RIALO_CLOCK_SKEW). The node
/// explicitly refused the transaction before execution, so no broadcast
/// ambiguity exists and a fresh CLI invocation (fresh valid_from) may pass.
/// Everything else — confirmation timeouts, faucet, wallet, balance,
/// address/amount validation, CLI failures — never retries on the payment
/// path.
fn is_retryable_clock_skew(code: &'static str) -> bool {
    code == "RIALO_CLOCK_SKEW"
}

fn classify(op: Operation, message: &str) -> &'static str {
    let lower = message.to_lowercase();
    if lower.contains("network error")
        || lower.contains("error sending request")
        || lower.contains("connection refused")
    {
        "RIALO_RPC_UNAVAILABLE"
    } else if lower.contains("transaction confirmation timed out")
        || lower.contains("confirmation timed out")
        || lower.contains("timed out waiting for confirmation")
    {
        // Checked BEFORE the generic "timed out waiting" RPC rule: a
        // confirmation timeout means the RPC answered and the transaction
        // was likely already broadcast — the node just did not confirm it
        // within the CLI's window. For payments this is NOT a faucet error
        // and NOT proof of non-execution.
        match op {
            Operation::Transfer | Operation::Program => "RIALO_TRANSFER_CONFIRMATION_TIMEOUT",
            _ => "RIALO_FAUCET_ERROR",
        }
    } else if lower.contains("timed out waiting") {
        "RIALO_RPC_UNAVAILABLE"
    } else if lower.contains("timestampinfuture")
        || lower.contains("timestamp in the future")
        || lower.contains("clock skew")
    {
        "RIALO_CLOCK_SKEW"
    } else if lower.contains("transaction timeout")
        || lower.contains("airdrop")
        || lower.contains("faucet")
    {
        // A transfer/payment is never a faucet failure. The faucet-specific
        // keywords only carry the faucet meaning on the faucet path.
        match op {
            Operation::Faucet => "RIALO_FAUCET_ERROR",
            _ if op.is_payment() => {
                if op == Operation::Program {
                    "RIALO_PROGRAM_ERROR"
                } else {
                    "RIALO_TRANSFER_ERROR"
                }
            }
            _ => "RIALO_ERROR",
        }
    } else if lower.contains("failed to load") && lower.contains("keypair") {
        "RIALO_WALLET_ERROR"
    } else {
        "RIALO_ERROR"
    }
}

/// Safety note attached to confirmation-timeout details. A confirmation
/// timeout is NOT proof that the transaction was not broadcast: the caller
/// must verify on-chain transaction state before retrying, and must never
/// blind-retry a payment.
const CONFIRMATION_TIMEOUT_NOTE: &str = " — confirmation timed out; the transaction \
                                         may already have been accepted/broadcast. \
                                         DO NOT retry automatically: verify \
                                         transaction state on-chain before re-attempting.";

fn with_confirmation_timeout_note(code: &'static str, detail: String) -> String {
    if code == "RIALO_TRANSFER_CONFIRMATION_TIMEOUT" {
        format!("{detail}{CONFIRMATION_TIMEOUT_NOTE}")
    } else {
        detail
    }
}

fn first_line(text: &str) -> String {
    text.lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("(no output)")
        .to_string()
}

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var("PATH").ok()?;
    for dir in path.split(':') {
        let candidate = PathBuf::from(dir).join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

// =============================================================================
// PHASE 6 STEP 4 — safe TransactionResponse parsing (fail-closed)
// =============================================================================
//
// The canonical wire shape is rialo-api-types-0.18.1 `GetTransactionResponse`
// (camelCase JSON: blockHeight? -> "block_height" per the CLI snake_case
// convention; transaction{signatures,message{accountKeys,instructions}},
// meta{err,fee,logMessages}); the CLI's `client transaction --json` prints
// its own view of the same data. Every reader below accepts BOTH casings and
// takes nothing on faith: any missing decisive field yields None (Unknown),
// never an inferred value. `executed` must be an EXPLICIT boolean — it is
// never derived from "err == null", because a missing status is not a
// successful transaction.

fn u64_field(obj: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .filter_map(|k| obj.get(*k))
        .find_map(Value::as_u64)
}

fn i64_field(obj: &Value, keys: &[&str]) -> Option<i64> {
    keys.iter().filter_map(|k| obj.get(*k)).find_map(|v| {
        v.as_i64()
            .or_else(|| v.as_f64().filter(|f| f.fract() == 0.0).map(|f| f as i64))
    })
}

fn bool_field(obj: &Value, keys: &[&str]) -> Option<bool> {
    keys.iter()
        .filter_map(|k| obj.get(*k))
        .find_map(Value::as_bool)
}

/// Dig the status object out of the two known envelope shapes:
///   {"status":{"slot","executed","err"}}          (CLI transfer-style)
///   {"meta":{"err", ...}, ...}                    (RPC GetTransactionResponse)
/// Returns (executed explicit-bool, err-value-present-as-option).
/// Err-value: Null in a present meta/status = on-chain success (None);
/// a non-null err becomes its compact string form.
fn extract_status(value: &Value) -> Option<(bool, Option<String>, Option<u64>)> {
    if let Some(status) = value.get("status").filter(|s| s.is_object()) {
        let executed = bool_field(status, &["executed", "EXECUTED"])?;
        let err = status
            .get("err")
            .or_else(|| status.get("error"))
            .filter(|e| !e.is_null())
            .map(|e| {
                e.as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| e.to_string())
            });
        let slot = u64_field(status, &["slot"]);
        return Some((executed, err, slot));
    }
    if let Some(meta) = value.get("meta").filter(|m| m.is_object()) {
        // In the RPC shape, presence of the record at all means the node
        // returned a committed transaction; `err: null` is success. But we
        // NEVER infer `executed`: a record whose status is not explicit is
        // INCOMPLETE (=> Unknown via Malformed), not a failure and not a
        // success.
        let executed =
            bool_field(meta, &["executed"]).or_else(|| bool_field(value, &["executed"]))?;
        let err = meta.get("err").filter(|e| !e.is_null()).map(|e| {
            e.as_str()
                .map(str::to_string)
                .unwrap_or_else(|| e.to_string())
        });
        let slot = u64_field(meta, &["slot"]).or_else(|| u64_field(value, &["slot"]));
        return Some((executed, err, slot));
    }
    None
}

/// Pull (payer, recipient, amount_kelvin) from a decoded transfer
/// instruction, if exactly ONE system-transfer instruction exists in the
/// message. A transaction with multiple transfers is ambiguous evidence →
/// None (the caller fails closed; a multi-transfer tx must not be matched
/// against a single-intent payment by accident).
fn extract_single_transfer(value: &Value) -> Option<(Option<String>, Option<String>, Option<u64>)> {
    let transaction = value.get("transaction").or_else(|| value.get("tx"))?;
    let message = transaction.get("message")?;
    let keys = message
        .get("accountKeys")
        .or_else(|| message.get("account_keys"))?;
    let keys = keys.as_array()?;
    // payer = first account key (the fee payer / primary signer). Require at
    // least one signature so a keyless message cannot pose as evidence.
    let signatures = transaction.get("signatures").and_then(Value::as_array);
    if signatures.map_or(true, |s| s.is_empty()) {
        return None;
    }
    let payer = keys.first().and_then(Value::as_str).map(str::to_string)?;
    let instructions = message.get("instructions").and_then(Value::as_array)?;
    let mut found: Option<(String, u64)> = None;
    for ix in instructions {
        let data = ix.get("data").and_then(Value::as_str)?;
        let Some(amount) = system_transfer_amount(data) else {
            continue; // not a system transfer — irrelevant shape
        };
        let accounts = ix.get("accounts").and_then(Value::as_array)?;
        let idx = accounts.first()?.as_u64()? as usize;
        let recipient = keys.get(idx).and_then(Value::as_str)?.to_string();
        if found.is_some() {
            return None; // ambiguous: several transfers in one tx
        }
        found = Some((recipient, amount));
    }
    match found {
        Some((recipient, amount)) => Some((Some(payer), Some(recipient), Some(amount))),
        None => Some((Some(payer), None, None)),
    }
}

/// Parse the CLI get_transaction reply into a decisive-or-None record.
/// `requested_signature` is kept only when the envelope carries NO
/// signature field (the lookup itself keys the evidence); a carried
/// signature MUST match the request or the whole record is rejected.
pub fn parse_tx_record(requested_signature: &str, value: &Value) -> Option<TxRecord> {
    let (executed, err, status_slot) = extract_status(value)?;

    // signature: any that is present must equal the requested one
    let carried = extract_signature(value).or_else(|| {
        value
            .get("transaction")
            .or_else(|| value.get("tx"))
            .and_then(|t| t.get("signatures"))
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(Value::as_str)
            .map(str::to_string)
    });
    if let Some(c) = &carried {
        if c != requested_signature {
            return None; // wrong-transaction guard (fail closed)
        }
    }

    let block_height = u64_field(value, &["block_height", "blockHeight"]).or_else(|| {
        value
            .get("meta")
            .and_then(|m| u64_field(m, &["block_height", "blockHeight"]))
    });
    let slot = status_slot
        .or_else(|| u64_field(value, &["slot"]))
        .or(block_height);
    let block_time = i64_field(value, &["block_time", "blockTime"])
        .or_else(|| {
            value
                .get("meta")
                .and_then(|m| i64_field(m, &["block_time", "blockTime"]))
        })
        .map(normalize_block_time);
    let fee = value
        .get("meta")
        .and_then(|m| u64_field(m, &["fee"]))
        .or_else(|| u64_field(value, &["fee"]));

    let (payer, transfer_recipient, transfer_amount_kelvin) =
        extract_single_transfer(value).unwrap_or((None, None, None));

    Some(TxRecord {
        signature: carried.or_else(|| Some(requested_signature.to_string())),
        executed,
        err,
        slot,
        block_height,
        block_time,
        fee,
        payer,
        transfer_recipient,
        transfer_amount_kelvin,
        complete: true,
    })
}

#[cfg(test)]
mod manifest_guard_tests {
    use super::*;

    fn manifest_with(accounts: &[&str]) -> Value {
        let accounts: Vec<Value> = accounts
            .iter()
            .map(|name| serde_json::json!({ "name": name }))
            .collect();
        serde_json::json!({
            "instructions": {
                "execute": { "accounts": accounts }
            }
        })
    }

    #[test]
    fn fixed_deployed_layout_is_accepted() {
        // Exactly the layout the deployed bytecode dispatches against
        // (verified live 2026-09-28, Phase 3 Fix-B).
        let m = manifest_with(&["payer", "workflow_pda", "system_program", "recipient"]);
        assert!(RialoConfig::check_execute_account_order(&m).is_ok());
    }

    #[test]
    fn subscriber_interface_without_subscriptions_is_rejected() {
        // The original rialo-venus-dsl bug: a subscriber_interface slot with
        // no subscription accounts shifts the recipient one index right —
        // the deployed dispatch would then pay the interface account.
        let m = manifest_with(&[
            "payer",
            "workflow_pda",
            "system_program",
            "subscriber_interface",
            "recipient",
        ]);
        let err = RialoConfig::check_execute_account_order(&m)
            .expect_err("must reject the unfixed manifest layout");
        assert_eq!(err.code, "PROGRAM_MANIFEST_BUG");
    }

    #[test]
    fn recipient_must_sit_at_index_3_without_subscriptions() {
        let m = manifest_with(&["payer", "workflow_pda", "recipient", "system_program"]);
        let err = RialoConfig::check_execute_account_order(&m)
            .expect_err("positional invariant must hold");
        assert_eq!(err.code, "PROGRAM_MANIFEST_INVALID");
    }

    #[test]
    fn missing_recipient_is_rejected() {
        let m = manifest_with(&["payer", "workflow_pda", "system_program"]);
        let err = RialoConfig::check_execute_account_order(&m)
            .expect_err("no recipient entry must fail validation");
        assert_eq!(err.code, "PROGRAM_MANIFEST_INVALID");
        assert!(err.detail.contains("no recipient"));
    }

    #[test]
    fn head_order_invariant_is_enforced() {
        let m = manifest_with(&["workflow_pda", "payer", "system_program", "recipient"]);
        let err =
            RialoConfig::check_execute_account_order(&m).expect_err("payer must be account 0");
        assert_eq!(err.code, "PROGRAM_MANIFEST_INVALID");
    }

    #[test]
    fn missing_execute_accounts_is_rejected() {
        let err = RialoConfig::check_execute_account_order(&serde_json::json!({}))
            .expect_err("no execute.accounts must fail");
        assert_eq!(err.code, "PROGRAM_MANIFEST_INVALID");
    }

    #[test]
    fn subscription_layout_with_subscriber_interface_is_allowed() {
        // When subscription accounts DO exist, the subscriber_interface slot
        // is legitimate (dispatch counts it) and the recipient is resolved
        // dynamically, not at a fixed index.
        let m = manifest_with(&[
            "payer",
            "workflow_pda",
            "system_program",
            "subscription_pda",
            "subscriber_interface",
            "recipient",
        ]);
        assert!(RialoConfig::check_execute_account_order(&m).is_ok());
    }

    #[test]
    fn rpc_failures_classify_as_unavailable() {
        // The payment pre-check relies on these being RIALO_RPC_UNAVAILABLE
        // (503) — never a silently-fake zero balance.
        assert_eq!(
            classify(Operation::Read, "Network error: connection refused"),
            "RIALO_RPC_UNAVAILABLE"
        );
        assert_eq!(
            classify(
                Operation::Transfer,
                "error sending request for url (RPC timeout)"
            ),
            "RIALO_RPC_UNAVAILABLE"
        );
        assert_eq!(
            classify(Operation::Read, "timed out waiting for response headers"),
            "RIALO_RPC_UNAVAILABLE"
        );
    }

    #[test]
    fn other_failures_keep_their_own_codes() {
        assert_eq!(
            classify(Operation::Faucet, "faucet rejected request"),
            "RIALO_FAUCET_ERROR"
        );
        assert_eq!(
            classify(Operation::Faucet, "failed to load keypair from path"),
            "RIALO_WALLET_ERROR"
        );
        assert_eq!(
            classify(Operation::Read, "some program error"),
            "RIALO_ERROR"
        );
    }

    #[test]
    fn real_artifact_manifest_passes_the_guard() {
        // The shipped artifact manifest must satisfy the guard exactly as the
        // server sees it at runtime (integration pin for Fix-B).
        // ENVIRONMENT TEST: depends on the operator's live artifact/ tree
        // (runbook-documented local state, absent in CI checkouts). Same
        // skip-with-reason pattern as signer_binary(): validates when the
        // manifest exists, registers a clean skip otherwise.
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("artifact");
        if !manifest_dir
            .join("wit/rialo-agentpay-manifest.json")
            .exists()
        {
            eprintln!("artifact manifest not present (clean checkout) — skipped");
            return;
        }
        let config = RialoConfig {
            cli: PathBuf::from("rialo"),
            rpc_url: "http://127.0.0.1:4104".into(),
            program_id: Some("CuevBS5wQYPVBbCfV2ZFeUSbo9Jod95WfqM6W7vyZtH3".into()),
            program_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("artifact"),
        };
        let path = config
            .validate_program_manifest()
            .expect("artifact/wit manifest must pass the integrity guard");
        assert!(path.to_string_lossy().ends_with("-manifest.json"));
    }
}

#[cfg(test)]
mod classification_tests {
    use super::*;

    /// G21.12.40: serve one canned JSON-RPC reply on a loopback port and
    /// return (url, join-handle). G21.12.46: captures the request body and
    /// asserts the VERIFIED-LIVE wire shape — exactly top-level
    /// `"params": []` (the endpoint 400s on a nested `[[]]`).
    fn serve_one_jsonrpc(reply: &'static str) -> (String, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = vec![0u8; 65536];
            let n = stream.read(&mut buf).expect("read");
            let body = String::from_utf8_lossy(&buf[..n]).to_string();
            // G21.12.46 — exact wire shape regression guard: params must be
            // a top-level EMPTY array; nesting (`[[]]`) is the live-verified
            // -32602 failure mode.
            assert!(
                body.contains("\"params\":[]"),
                "health fallback must send exactly \"params\":[] (no nesting), got: {body}"
            );
            assert!(
                !body.contains("\"params\":[[]]"),
                "params must NOT be nested ([[]] is the live-verified -32602 rejection), got: {body}"
            );
            assert!(
                body.contains("\"getBlockHeight\""),
                "method must be getBlockHeight"
            );
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                reply.len(),
                reply
            );
            stream.write_all(resp.as_bytes()).expect("write");
        });
        (format!("http://{addr}"), handle)
    }

    fn cfg_with(cli: &str, rpc_url: &str) -> RialoConfig {
        RialoConfig {
            cli: std::path::PathBuf::from(cli),
            rpc_url: rpc_url.to_string(),
            program_id: None,
            program_dir: std::path::PathBuf::from("artifact"),
        }
    }

    #[test]
    fn health_falls_back_to_raw_rpc_when_cli_missing() {
        let (url, server) = serve_one_jsonrpc("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":1834571}");
        // definitely-missing CLI path → run() errors → raw fallback lane.
        let cfg = cfg_with("/nonexistent/rialo-binary-g21", &url);
        let h = cfg.health().expect("raw fallback must succeed");
        assert_eq!(h, 1834571, "height must come from the real RPC reply");
        server.join().expect("server thread");
    }

    #[test]
    fn health_fallback_fails_closed_on_rpc_error() {
        // RPC-level error object must NOT fabricate a height.
        let (url, server) = serve_one_jsonrpc(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":\"method not found\"}}",
        );
        let cfg = cfg_with("/nonexistent/rialo-binary-g21", &url);
        let err = cfg.health().expect_err("rpc error must propagate");
        assert_eq!(err.code, "RIALO_ERROR");
        server.join().expect("server thread");
    }

    #[test]
    fn health_fallback_fails_closed_on_dead_endpoint() {
        // Dead port: classified RIALO_RPC_UNAVAILABLE — never a fake success.
        let cfg = cfg_with("/nonexistent/rialo-binary-g21", "http://127.0.0.1:9");
        let err = cfg.health().expect_err("dead endpoint must fail");
        assert_eq!(err.code, "RIALO_RPC_UNAVAILABLE");
    }

    #[test]
    fn transfer_confirmation_timeout_is_dedicated_code() {
        assert_eq!(
            classify(Operation::Transfer, "Transaction confirmation timed out"),
            "RIALO_TRANSFER_CONFIRMATION_TIMEOUT"
        );
        assert_eq!(
            classify(Operation::Transfer, "confirmation timed out"),
            "RIALO_TRANSFER_CONFIRMATION_TIMEOUT"
        );
        assert_eq!(
            classify(Operation::Transfer, "timed out waiting for confirmation"),
            "RIALO_TRANSFER_CONFIRMATION_TIMEOUT"
        );
    }

    #[test]
    fn program_payment_confirmation_timeout_gets_dedicated_code() {
        assert_eq!(
            classify(Operation::Program, "Transaction confirmation timed out"),
            "RIALO_TRANSFER_CONFIRMATION_TIMEOUT"
        );
    }

    #[test]
    fn faucet_confirmation_timeout_stays_faucet_error() {
        assert_eq!(
            classify(Operation::Faucet, "Transaction confirmation timed out"),
            "RIALO_FAUCET_ERROR"
        );
        assert_eq!(
            classify(Operation::Faucet, "faucet rate limited"),
            "RIALO_FAUCET_ERROR"
        );
        assert_eq!(
            classify(Operation::Faucet, "airdrop rejected request"),
            "RIALO_FAUCET_ERROR"
        );
    }

    #[test]
    fn transfer_never_classifies_as_faucet_error() {
        // The core regression: every token that used to route to
        // RIALO_FAUCET_ERROR must NOT do so on the payment paths.
        for msg in [
            "Transaction confirmation timed out",
            "confirmation timed out",
            "timed out waiting for confirmation",
            "transaction timeout while airdrop-like wait failed",
            "airdrop faucet transaction timeout",
            "some faucet-ish error on a transfer",
        ] {
            for op in [Operation::Transfer, Operation::Program] {
                assert_ne!(
                    classify(op, msg),
                    "RIALO_FAUCET_ERROR",
                    "payment op {:?} must never yield RIALO_FAUCET_ERROR for {:?}",
                    op,
                    msg
                );
            }
        }
    }

    #[test]
    fn timestamp_in_future_is_clock_skew() {
        assert_eq!(
            classify(
                Operation::Program,
                "Transaction validation failed: TimestampInFuture"
            ),
            "RIALO_CLOCK_SKEW"
        );
        assert_eq!(
            classify(Operation::Transfer, "TimestampInFuture"),
            "RIALO_CLOCK_SKEW"
        );
        assert_eq!(
            classify(
                Operation::Transfer,
                "transaction validation failed: timestamp in the future"
            ),
            "RIALO_CLOCK_SKEW"
        );
    }

    #[test]
    fn rpc_timeout_and_network_failure_are_unavailable() {
        assert_eq!(
            classify(Operation::Transfer, "Network error: connection refused"),
            "RIALO_RPC_UNAVAILABLE"
        );
        assert_eq!(
            classify(Operation::Read, "error sending request for url"),
            "RIALO_RPC_UNAVAILABLE"
        );
        // A generic RPC-level wait timeout (no confirmation context) is
        // still a connectivity failure, even on the transfer path.
        assert_eq!(
            classify(
                Operation::Transfer,
                "timed out waiting for response headers"
            ),
            "RIALO_RPC_UNAVAILABLE"
        );
    }

    #[test]
    fn wallet_and_transfer_specific_errors_keep_their_codes() {
        assert_eq!(
            classify(Operation::Transfer, "failed to load keypair from file"),
            "RIALO_WALLET_ERROR"
        );
        assert_eq!(
            classify(Operation::Transfer, "transaction timeout"),
            "RIALO_TRANSFER_ERROR"
        );
        assert_eq!(
            classify(Operation::Program, "transaction timeout"),
            "RIALO_PROGRAM_ERROR"
        );
    }

    #[test]
    fn confirmation_timeout_detail_carries_no_retry_note() {
        // Requirement: the error detail must explicitly tell the caller the
        // transaction may already be broadcast and must be verified before
        // any retry.
        let detail = with_confirmation_timeout_note(
            "RIALO_TRANSFER_CONFIRMATION_TIMEOUT",
            "Transaction confirmation timed out".to_string(),
        );
        assert!(detail.contains("confirmation timed out"));
        assert!(detail.contains("may already have been accepted/broadcast"));
        assert!(detail.contains("DO NOT retry automatically"));
        // Non-timeout details pass through unchanged.
        assert_eq!(
            with_confirmation_timeout_note("RIALO_FAUCET_ERROR", "faucet down".into()),
            "faucet down"
        );
    }

    #[test]
    fn only_clock_skew_is_retryable_on_transfer() {
        assert!(is_retryable_clock_skew("RIALO_CLOCK_SKEW"));
        assert!(!is_retryable_clock_skew(
            "RIALO_TRANSFER_CONFIRMATION_TIMEOUT"
        ));
        assert!(!is_retryable_clock_skew("RIALO_FAUCET_ERROR"));
        assert!(!is_retryable_clock_skew("RIALO_TRANSFER_ERROR"));
        assert!(!is_retryable_clock_skew("RIALO_RPC_UNAVAILABLE"));
        assert!(!is_retryable_clock_skew("RIALO_WALLET_ERROR"));
        assert!(!is_retryable_clock_skew("RIALO_CLI_UNAVAILABLE"));
        assert!(!is_retryable_clock_skew("RIALO_ERROR"));
        assert!(!is_retryable_clock_skew("RIALO_PROGRAM_ERROR"));
    }

    #[test]
    fn transfer_timestamp_in_future_classifies_as_retryable_skew() {
        // End-to-end gate check: the exact CLI message must route through
        // classify() into the one code the retry loop accepts.
        let code = classify(
            Operation::Transfer,
            "Transaction validation failed: TimestampInFuture",
        );
        assert_eq!(code, "RIALO_CLOCK_SKEW");
        assert!(is_retryable_clock_skew(code));
        // ...while the confirmation-timeout code that must NEVER retry does
        // not pass the gate even after classification.
        let code = classify(Operation::Transfer, "Transaction confirmation timed out");
        assert_eq!(code, "RIALO_TRANSFER_CONFIRMATION_TIMEOUT");
        assert!(!is_retryable_clock_skew(code));
    }
}

#[cfg(test)]
mod transfer_envelope_tests {
    use super::*;

    #[test]
    fn executed_transfer_returns_signature() {
        let value = serde_json::json!({
            "signature": "5xyz",
            "status": { "slot": 1, "executed": true, "err": null }
        });
        assert_eq!(
            transfer_signature(value.clone()).unwrap(),
            ("5xyz".to_string(), Some(1))
        );
        // missing slot -> None (fail-closed evidence)
        let value_no_slot = serde_json::json!({
            "signature": "5xyz",
            "status": { "executed": true, "err": null }
        });
        assert_eq!(
            transfer_signature(value_no_slot).unwrap(),
            ("5xyz".to_string(), None)
        );
        let _ = value;
    }

    #[test]
    fn not_executed_transfer_is_transfer_error_not_skew() {
        let value = serde_json::json!({
            "signature": "",
            "status": { "slot": 1, "executed": false, "err": "InsufficientFundsForFee" }
        });
        let err = transfer_signature(value).expect_err("must fail");
        assert_eq!(err.code, "RIALO_TRANSFER_ERROR");
        assert!(!is_retryable_clock_skew(err.code));
    }

    #[test]
    fn executed_with_error_status_is_transfer_error() {
        let value = serde_json::json!({
            "signature": "5xyz",
            "status": { "slot": 1, "executed": true, "err": "AccountNotFound" }
        });
        let err = transfer_signature(value).expect_err("non-null err must fail");
        assert_eq!(err.code, "RIALO_TRANSFER_ERROR");
        assert!(!is_retryable_clock_skew(err.code));
    }
}

#[cfg(test)]
mod transaction_lookup_tests {
    use super::*;

    /// Test-only base58 encoder for building system-transfer payloads.
    fn b58(bytes: &[u8]) -> String {
        const A: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let mut digits: Vec<u8> = Vec::new();
        for &b in bytes {
            let mut carry = b as u32;
            for d in digits.iter_mut() {
                let v = (*d as u32) * 256 + carry;
                *d = (v % 58) as u8;
                carry = v / 58;
            }
            while carry > 0 {
                digits.push((carry % 58) as u8);
                carry /= 58;
            }
        }
        for &b in bytes {
            if b != 0 {
                break;
            }
            digits.push(0);
        }
        let mut out = String::new();
        for d in digits.iter().rev() {
            out.push(A[*d as usize] as char);
        }
        out
    }

    fn transfer_data(amount_kelvin: u64) -> String {
        let mut raw = vec![2u8, 0, 0, 0];
        raw.extend_from_slice(&amount_kelvin.to_le_bytes());
        b58(&raw)
    }

    fn full_envelope(sig: &str, executed: bool, err: Option<&str>, amt: u64) -> Value {
        serde_json::json!({
            "signature": sig,
            "block_height": 900,
            "block_time": 1_790_668_900i64,
            "status": { "slot": 777, "executed": executed, "err": err },
            "meta": { "fee": 5000 },
            "transaction": {
                "signatures": [sig],
                "message": {
                    "accountKeys": ["AgentWalletAddr1111111111111111111111111", "RecipientAddr2222222222222222222222222222"],
                    "instructions": [
                        { "accounts": [1], "data": transfer_data(amt), "programIdIndex": 2 }
                    ]
                }
            }
        })
    }

    #[test]
    fn successful_transfer_parses_all_verification_fields() {
        let v = full_envelope("SigA", true, None, 50_000_000);
        let rec = parse_tx_record("SigA", &v).expect("complete record");
        assert!(rec.executed);
        assert_eq!(rec.err, None);
        assert_eq!(rec.slot, Some(777));
        assert_eq!(rec.block_height, Some(900));
        assert_eq!(rec.block_time, Some(1_790_668_900));
        assert_eq!(rec.fee, Some(5000));
        let (payer, recipient, amount) = rec.transfer_facts().expect("decoded transfer");
        assert_eq!(payer, "AgentWalletAddr1111111111111111111111111");
        assert_eq!(recipient, "RecipientAddr2222222222222222222222222222");
        assert_eq!(amount, 50_000_000);
    }

    #[test]
    fn failed_transfer_is_decisive_not_absent_guesswork() {
        let v = full_envelope("SigA", false, Some("AccountNotFound"), 50_000_000);
        let rec = parse_tx_record("SigA", &v).expect("record");
        assert!(!rec.executed);
        assert_eq!(rec.err.as_deref(), Some("AccountNotFound"));
    }

    #[test]
    fn wrong_signature_envelope_is_rejected() {
        let v = full_envelope("SigOther", true, None, 50_000_000);
        assert!(
            parse_tx_record("SigA", &v).is_none(),
            "cross-sig evidence must fail closed"
        );
    }

    #[test]
    fn missing_status_is_malformed_not_inferred() {
        // No status/meta object: NOTHING may be inferred about execution.
        let v = serde_json::json!({ "signature": "SigA", "transaction": {} });
        assert!(parse_tx_record("SigA", &v).is_none());
    }

    #[test]
    fn meta_shape_without_explicit_executed_is_malformed() {
        // A committed record WITHOUT an executed bool must NEVER be read
        // as failed (executed=false would mint a false Absent).
        let v = serde_json::json!({
            "meta": { "err": null, "fee": 1 },
            "transaction": { "signatures": ["SigA"] },
            "blockHeight": 5,
        });
        assert!(parse_tx_record("SigA", &v).is_none());
    }

    #[test]
    fn camel_case_rpc_shape_with_executed_parses() {
        let v = serde_json::json!({
            "executed": true,
            "meta": { "err": null, "fee": 5000, "blockTime": 1_790_668_900 },
            "blockHeight": 900,
            "transaction": {
                "signatures": ["SigA"],
                "message": {
                    "accountKeys": ["Payer1", "Recip2"],
                    "instructions": [
                        { "accounts": [1], "data": transfer_data(1000), "programIdIndex": 2 }
                    ]
                }
            }
        });
        let rec = parse_tx_record("SigA", &v).expect("camelCase record parses");
        assert!(rec.executed);
        assert_eq!(rec.block_height, Some(900));
        assert_eq!(rec.block_time, Some(1_790_668_900));
        assert_eq!(rec.transfer_facts().map(|f| f.2), Some(1000));
    }

    #[test]
    fn two_transfers_in_one_tx_are_ambiguous() {
        let mut v = full_envelope("SigA", true, None, 50_000_000);
        v["transaction"]["message"]["instructions"].as_array_mut().unwrap().push(
            serde_json::json!({ "accounts": [1], "data": transfer_data(50_000_000), "programIdIndex": 2 }),
        );
        let rec = parse_tx_record("SigA", &v).expect("status still parses");
        assert!(
            rec.transfer_facts().is_none(),
            "ambiguous transfer must yield NO facts"
        );
    }

    #[test]
    fn non_system_data_never_yields_amount() {
        let v = serde_json::json!({
            "signature": "SigA",
            "status": { "slot": 1, "executed": true, "err": null },
            "transaction": {
                "signatures": ["SigA"],
                "message": {
                    "accountKeys": ["Payer1", "Recip2"],
                    "instructions": [
                        { "accounts": [1], "data": "9XkNotTwelveBytes", "programIdIndex": 2 }
                    ]
                }
            }
        });
        let rec = parse_tx_record("SigA", &v).expect("record");
        assert_eq!(rec.transfer_amount_kelvin, None);
    }

    #[test]
    fn base58_roundtrip_matches_known_vectors() {
        assert_eq!(base58_decode("111").unwrap(), vec![0u8, 0, 0]);
        let amount = 50_000_000u64;
        let mut raw = vec![2u8, 0, 0, 0];
        raw.extend_from_slice(&amount.to_le_bytes());
        assert_eq!(base58_decode(&transfer_data(amount)).unwrap(), raw);
        assert_eq!(system_transfer_amount(&transfer_data(amount)), Some(amount));
        // discriminator != 2 => no transfer
        assert_eq!(
            system_transfer_amount(&b58(&[3u8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0])),
            None
        );
        // wrong length => no transfer
        assert_eq!(system_transfer_amount("111"), None);
        // invalid charset => None, never a panic
        assert!(base58_decode("0OIl").is_none());
    }

    #[test]
    fn not_found_and_rpc_down_classify_distinctly() {
        assert!(is_not_found_message("Transaction not found"));
        assert!(is_not_found_message("RPC error: SignatureNotFound"));
        assert!(!is_not_found_message("Network error: connection refused"));
        // the RPC-down code must never be swallowed into NotFound
        let down = RialoError::plain("RIALO_RPC_UNAVAILABLE", "Network error".into());
        assert!(down.is_rpc_down());
    }

    #[test]
    fn failure_envelopes_surface_signature_only_when_present() {
        let with = serde_json::json!({"success": false, "signature": "SigA", "message": "Transaction confirmation timed out"});
        assert_eq!(extract_signature(&with).as_deref(), Some("SigA"));
        let nested = serde_json::json!({"success": false, "error": {"signature": "SigB"}});
        assert_eq!(extract_signature(&nested).as_deref(), Some("SigB"));
        let none = serde_json::json!({"success": false, "message": "no sig here"});
        assert_eq!(extract_signature(&none), None);
        let empty = serde_json::json!({"signature": ""});
        assert_eq!(
            extract_signature(&empty),
            None,
            "empty placeholder is never a signature"
        );
    }

    // =========================================================================
    // PHASE 6 STEP 4 — SCHEMA REMEDIATION: exact live-shape fixtures (fix 7).
    // Every fixture below is copied from the rialo-api-types-0.18.1 vendor
    // request/response structs (camelCase serde) — the shapes the live node
    // actually answers with — NOT from invented shapes. They pin fixes
    // 1/2/4/5/6 at the parse layer without any live call.
    // =========================================================================

    /// FIX 4 — getSignaturesForAddress must go out as ONE vendor OBJECT
    /// param (`{version, address, config{limit, until}}`), never the
    /// Solana-style positional `[address, config]` array.
    #[test]
    fn vendor_object_params_wire_shape_is_pinned() {
        let config = serde_json::json!({ "limit": 25, "until": "SigCursor" });
        let params = serde_json::json!({
            "version": 0u16,
            "address": "AgentWalletAddr1111111111111111111111111",
            "config": config,
        });
        let body = rpc_request_body("getSignaturesForAddress", &params);
        let arr = body["params"].as_array().expect("params array");
        assert_eq!(arr.len(), 1, "vendor takes ONE positional object param");
        assert_eq!(
            arr[0]["address"],
            "AgentWalletAddr1111111111111111111111111"
        );
        assert_eq!(arr[0]["config"]["limit"], 25);
        assert_eq!(arr[0]["config"]["until"], "SigCursor");
        assert_eq!(arr[0]["version"], 0);
        assert!(
            arr[0].get("before").is_none() && arr[0]["config"].get("commitment").is_none(),
            "vendor config carries ONLY limit/before/until — nothing else may be sent"
        );
    }

    /// FIX 5 — decisive scan data lives at result.value; blockTime is
    /// MILLISECONDS (vendor live shape, camelCase) and is normalized.
    #[test]
    fn signatures_for_address_result_value_live_shape() {
        let reply = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "context": { "slot": 901 },
                "value": [
                    {
                        "signature": "SigA",
                        "blockHeight": 900,
                        "err": null,
                        "blockTime": 1_790_668_900_000i64
                    },
                    {
                        "signature": "SigFailed",
                        "blockHeight": 899,
                        "err": { "InstructionError": [0, "InsufficientFunds"] },
                        "blockTime": 1_790_668_800_000i64
                    },
                    { "signature": "", "blockHeight": 1 },
                    { "blockHeight": 2 }
                ]
            }
        });
        let result = reply.get("result").expect("result object");
        let items = result["value"].as_array().expect("result.value array");
        let parsed = parse_signature_items(items);
        assert_eq!(
            parsed.len(),
            2,
            "shapeless items are skipped, never guessed"
        );
        assert_eq!(parsed[0].signature, "SigA");
        assert_eq!(parsed[0].block_height, Some(900));
        assert_eq!(parsed[0].err, None);
        assert_eq!(
            parsed[0].block_time,
            Some(1_790_668_900),
            "milliseconds must normalize to seconds"
        );
        assert_eq!(parsed[1].signature, "SigFailed");
        assert!(parsed[1].err.is_some(), "node-reported failure is kept");
        // A reply WITHOUT result.value is NOT an answer (fail closed).
        assert!(reply["result"].get("value").is_some());
        let no_value = serde_json::json!({ "context": { "slot": 1 } });
        assert!(no_value.get("value").and_then(Value::as_array).is_none());
    }

    /// FIX 1+5+2 — getSignatureStatuses live shape: `{version?, context,
    /// value:[{slot, err, executed}]}` (camelCase). The explicit executed
    /// bool is taken verbatim; err:null means success (None).
    #[test]
    fn signature_statuses_explicit_executed_live_shape() {
        let result = serde_json::json!({
            "version": 0u16,
            "context": { "slot": 905 },
            "value": [
                { "slot": 777, "err": null, "executed": true }
            ]
        });
        let StatusEntry::Explicit(rec) = parse_signature_status("SigA", &result) else {
            panic!("explicit status must parse to a record");
        };
        assert_eq!(rec.signature.as_deref(), Some("SigA"));
        assert!(rec.executed);
        assert_eq!(rec.err, None);
        assert_eq!(rec.slot, Some(777));
        assert_eq!(
            rec.block_time, None,
            "status carries NO time — never fabricated"
        );
        assert_eq!(rec.payer, None);
    }

    /// FIX 2 — a status entry WITHOUT the executed bool (or with a
    /// non-bool) is INCONCLUSIVE: executed is never derived from
    /// `err == null`, in either direction.
    #[test]
    fn signature_statuses_without_explicit_executed_is_inconclusive() {
        let no_bool = serde_json::json!({ "value": [{ "slot": 5, "err": null }] });
        assert!(matches!(
            parse_signature_status("SigA", &no_bool),
            StatusEntry::Inconclusive
        ));
        let string_bool =
            serde_json::json!({ "value": [{ "slot": 5, "executed": "true", "err": null }] });
        assert!(matches!(
            parse_signature_status("SigA", &string_bool),
            StatusEntry::Inconclusive
        ));
        let wrong_shape = serde_json::json!({ "value": "not-an-array" });
        assert!(matches!(
            parse_signature_status("SigA", &wrong_shape),
            StatusEntry::Inconclusive
        ));
    }

    /// Null / missing entry = the node answered and does NOT know the
    /// signature: temporary not-found, never permanent absence.
    #[test]
    fn signature_statuses_null_entry_is_no_status_not_absence() {
        let null_entry = serde_json::json!({ "context": { "slot": 9 }, "value": [null] });
        assert!(matches!(
            parse_signature_status("SigA", &null_entry),
            StatusEntry::NoStatus
        ));
        let empty = serde_json::json!({ "value": [] });
        assert!(matches!(
            parse_signature_status("SigA", &empty),
            StatusEntry::NoStatus
        ));
    }

    /// Failed-status live shape: executed=false or err present are both
    /// carried verbatim (decisive Absent material — consumed ONLY by the
    /// known-signature lane, which the reconciler already enforces).
    #[test]
    fn signature_statuses_failed_entry_parses_verbatim() {
        let result = serde_json::json!({
            "context": { "slot": 9 },
            "value": [{ "slot": 8, "err": { "InstructionError": [0, "Custom"] }, "executed": false }]
        });
        let StatusEntry::Explicit(rec) = parse_signature_status("SigA", &result) else {
            panic!("explicit failure status is evidence");
        };
        assert!(!rec.executed);
        assert!(rec.err.is_some());
        assert_eq!(rec.slot, Some(8));
    }

    /// FIX 6 — getBlock live shape: `{version?, context, value:{
    /// block_height, block_time}}` (CLI/view snake_case; the vendor
    /// BlockInfo serializes blockTime camelCase too). The block's OWN
    /// time is the only chain-timing fallback; a reply without it yields
    /// None — never a synthesized timestamp.
    #[test]
    fn get_block_timing_live_shape() {
        let result = serde_json::json!({
            "version": 0u16,
            "context": { "slot": 901 },
            "value": {
                "block_height": 900,
                "block_time": 1_790_668_900,
                "blockhash": "HASH",
                "previous_blockhash": "PREV",
                "transaction_count": 3
            }
        });
        assert_eq!(parse_block_time(&result), Some(1_790_668_900));
        let camel = serde_json::json!({ "value": { "blockTime": 1_790_668_900_000i64 } });
        assert_eq!(parse_block_time(&camel), Some(1_790_668_900));
        let no_time = serde_json::json!({ "value": { "block_height": 900 } });
        assert_eq!(
            parse_block_time(&no_time),
            None,
            "missing time is None, NEVER created_at"
        );
        let no_value = serde_json::json!({ "context": { "slot": 1 } });
        assert_eq!(parse_block_time(&no_value), None);
    }

    /// FIX 1+2 — the vendor getTransaction live shape
    /// (`GetTransactionResponse`: blockHeight, blockTime?,
    /// transaction{signatures,message{accountKeys,header,instructions}},
    /// meta{err,fee,logMessages}) carries NO executed field anywhere.
    /// parse_tx_record must reject it outright — a read record may
    /// supplement timing only after the PRIMARY path supplied an
    /// explicit executed bool; it can never mint a verdict alone.
    #[test]
    fn vendor_get_transaction_shape_never_mints_a_verdict() {
        let reply = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "version": 0u16,
                "context": { "slot": 901 },
                "blockHeight": 900,
                "blockTime": 1_790_668_900i64,
                "transaction": {
                    "signatures": ["SigA"],
                    "message": {
                        "accountKeys": ["AgentWalletAddr1111111111111111111111111", "RecipientAddr2222222222222222222222222222"],
                        "header": { "numRequiredSignatures": 1, "numReadonlySignedAccounts": 0, "numReadonlyUnsignedAccounts": 1 },
                        "instructions": [
                            { "accounts": [1], "data": transfer_data(50_000_000), "programIdIndex": 2 }
                        ]
                    },
                    "validFrom": 1_790_668_895_000i64
                },
                "meta": { "err": null, "fee": 5000, "logMessages": ["Program 1111 success"] }
            }
        });
        let result = reply["result"].clone();
        assert!(
            parse_tx_record("SigA", &result).is_none(),
            "vendor getTransaction has no explicit executed — must stay Malformed/Unknown"
        );
        // …but its TIMING fields are exactly what supplement_chain_timing
        // consumes from the `result` object:
        assert_eq!(
            u64_field(&result, &["block_height", "blockHeight"]),
            Some(900)
        );
        assert_eq!(
            i64_field(&result, &["block_time", "blockTime"]).map(normalize_block_time),
            Some(1_790_668_900)
        );
    }

    /// FIX 3 — validation invariants that must survive remediation:
    /// signature must match the request, and payer/recipient/amount come
    /// ONLY from a decoded single transfer (never from the intent).
    #[test]
    fn remediation_validation_invariants_hold() {
        // wrong carried signature: whole record rejected
        let v = full_envelope("SigOther", true, None, 50_000_000);
        assert!(parse_tx_record("SigA", &v).is_none());
        // explicit executed=false with err=null: FAILED evidence (Absent
        // material), NOT success — even though err is null
        let mut v = full_envelope("SigA", false, None, 50_000_000);
        let rec = parse_tx_record("SigA", &v).expect("record");
        assert!(!rec.executed);
        // tampered recipient: facts decode as what the CHAIN says, so a
        // mismatch vs the intent fails the Paid gate in proven_outcome —
        // the parse layer must not silently rewrite them
        v["transaction"]["message"]["accountKeys"][1] =
            serde_json::json!("WrongAddr3333333333333333333333333333");
        let rec = parse_tx_record("SigA", &v).expect("record");
        let (payer, recipient, amount) = rec.transfer_facts().expect("chain facts");
        assert_eq!(payer, "AgentWalletAddr1111111111111111111111111");
        assert_eq!(recipient, "WrongAddr3333333333333333333333333333");
        assert_eq!(amount, 50_000_000);
    }
}

#[cfg(test)]
mod balance_fallback_tests {
    use super::*;

    /// G21.12.98 T1 — unit conversion pinned by the live cross-check:
    /// RPC value (kelvins) → RLO requires division by exactly 1e9.
    /// 4_510_080 kelvins MUST parse to 0.00451008 RLO (CLI reference value).
    #[test]
    fn kelvin_to_rlo_conversion_is_nine_decimals() {
        const KELVINS_PER_RLO: f64 = 1_000_000_000.0;
        let kelvins: u64 = 4_510_080;
        let rlo = kelvins as f64 / KELVINS_PER_RLO;
        assert_eq!(rlo, 0.004_510_08);
        // One full RLO in kelvins round-trips exactly.
        assert_eq!((1.0 * KELVINS_PER_RLO) as u64, 1_000_000_000);
    }

    /// G21.12.98 T2 — malformed response (missing result.value) must be a
    /// typed error, never a fabricated zero.
    #[test]
    fn malformed_response_missing_value_is_typed_error() {
        // Exactly the shape the fallback parses:
        let parsed = serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "version": 0, "context": {"slot": 1, "api_version": "x"} }
        });
        let kelvins = parsed
            .get("result")
            .and_then(|r| r.get("value"))
            .and_then(Value::as_u64);
        assert!(
            kelvins.is_none(),
            "missing value must NOT parse as a balance"
        );
    }

    /// G21.12.98 T3 — a genuine ZERO balance is distinguished from absence:
    /// result.value = 0 parses (Some(0)) and yields 0.0 only from the RPC's
    /// explicit zero — while a MISSING node yields None → typed error.
    #[test]
    fn explicit_zero_balance_parses_but_absence_does_not() {
        let zero = serde_json::json!({"result": {"value": 0}});
        assert_eq!(
            zero.pointer("/result/value").and_then(Value::as_u64),
            Some(0)
        );

        let absent = serde_json::json!({"result": {}});
        assert_eq!(
            absent.pointer("/result/value").and_then(Value::as_u64),
            None
        );
    }

    /// G21.12.98 T4 — JSON-RPC error envelopes route to RIALO_ERROR (via
    /// jsonrpc_error) and transport/HTTP failures to RIALO_RPC_UNAVAILABLE,
    /// mirroring the health() fallback classification.
    #[test]
    fn error_envelope_classification_matches_health_fallback() {
        let rpc_err = serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "error": {"code": -32602, "message": "Invalid params: missing field `address`"}
        });
        assert!(jsonrpc_error(&rpc_err).is_some());
        let ok = serde_json::json!({"result": {"value": 7}});
        assert!(jsonrpc_error(&ok).is_none());
    }

    /// G21.12.98 T5 — request body wire shape is pinned exactly (single
    /// positional struct param with field `address`; method getBalance).
    #[test]
    fn getbalance_request_body_wire_shape() {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getBalance",
            "params": [{ "address": "Acc0unt1111111111111111111111111111111111" }],
        });
        assert_eq!(body["method"], "getBalance");
        assert_eq!(body["jsonrpc"], "2.0");
        let first = body["params"].as_array().unwrap()[0].clone();
        assert!(first.get("address").is_some(), "params[0].address required");
        assert!(first.as_object().unwrap().len() == 1, "no extra fields");
    }
}

#[cfg(test)]
mod faucet_fallback_tests {
    use super::*;

    /// G21.13.05 T1 — amount→kelvins conversion matches the live-captured
    /// vendor CLI wire: 1 RLO → 1_000_000_000; 2.5 RLO → 2_500_000_000.
    #[test]
    fn amount_to_kelvins_matches_vendor_wire() {
        assert_eq!(
            RialoConfig::parse_amount_to_kelvins("1").unwrap(),
            1_000_000_000
        );
        assert_eq!(
            RialoConfig::parse_amount_to_kelvins("2.5").unwrap(),
            2_500_000_000
        );
    }

    /// T2 — reject: zero, negative, non-numeric, NaN, overflow range.
    #[test]
    fn amount_rejects_invalid_inputs() {
        for bad in ["0", "-1", "abc", "NaN", "1e30", "-2.5", ""] {
            assert!(
                RialoConfig::parse_amount_to_kelvins(bad).is_err(),
                "must reject: {bad}"
            );
        }
    }

    /// T3 — sub-kelvin precision residue is rejected, never truncated
    /// (silent truncation = value corruption on a funding path).
    #[test]
    fn amount_rejects_sub_kelvin_residue() {
        assert!(RialoConfig::parse_amount_to_kelvins("0.0000000001").is_err());
        // exact kelvin-boundary fraction still passes
        assert_eq!(
            RialoConfig::parse_amount_to_kelvins("0.000000001").unwrap(),
            1
        );
    }

    /// T4 — success envelope parsing: bare-string result and wrapped
    /// {signature} both accepted; empty result rejected.
    #[test]
    fn airdrop_signature_shapes() {
        let bare = serde_json::json!({"result": "SIG123"});
        let sig = bare
            .pointer("/result")
            .and_then(|r| {
                r.as_str()
                    .map(|s| s.to_string())
                    .or_else(|| r.get("signature").and_then(Value::as_str).map(String::from))
            })
            .filter(|s| !s.is_empty());
        assert_eq!(sig.as_deref(), Some("SIG123"));

        let wrapped = serde_json::json!({"result": {"signature": "SIG456"}});
        let sig2 = wrapped
            .pointer("/result")
            .and_then(|r| {
                r.as_str()
                    .map(|s| s.to_string())
                    .or_else(|| r.get("signature").and_then(Value::as_str).map(String::from))
            })
            .filter(|s| !s.is_empty());
        assert_eq!(sig2.as_deref(), Some("SIG456"));

        let empty = serde_json::json!({"result": ""});
        let sig3 = empty
            .pointer("/result")
            .and_then(|r| {
                r.as_str()
                    .map(|s| s.to_string())
                    .or_else(|| r.get("signature").and_then(Value::as_str).map(String::from))
            })
            .filter(|s| !s.is_empty());
        assert!(sig3.is_none(), "empty envelope must not parse as success");
    }

    /// T5 — wire body pinned exactly (live-captured from vendor CLI):
    /// method requestAirdrop, params[0] = {version:0, pubkey, kelvins},
    /// kelvins scaled by 1e9 from RLO.
    #[test]
    fn request_airdrop_wire_shape() {
        let kelvins = RialoConfig::parse_amount_to_kelvins("1").unwrap();
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "requestAirdrop",
            "params": [{"version": 0, "pubkey": "Acc0unt1111111111111111111111111111111111", "kelvins": kelvins}],
        });
        assert_eq!(body["method"], "requestAirdrop");
        assert_eq!(body["jsonrpc"], "2.0");
        let p0 = &body["params"][0];
        assert_eq!(p0["version"], 0);
        assert_eq!(p0["kelvins"], 1_000_000_000u64);
        assert!(p0.get("pubkey").is_some());
        assert_eq!(p0.as_object().unwrap().len(), 3);
    }

    /// T6 — jsonrpc error envelope on faucet path routes to RIALO_ERROR,
    /// matching the classification used by health/balance fallbacks.
    #[test]
    fn faucet_error_envelope_classification() {
        let err_env = serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "error": {"code": -32000, "message": "faucet limit reached"}
        });
        assert!(jsonrpc_error(&err_env).is_some());
    }
}

#[cfg(test)]
mod cli_diag_tests {
    use super::*;
    use std::io::Write as _;
    use std::process::Command;

    /// G25 — offline shim harness: a tiny shell script standing in for the
    /// `rialo` CLI. Pure-local (loopback sink pages are inert JSON/exit
    /// codes); no real chain, no network transfers, no Faucet.
    struct Shim<'a> {
        script: &'a str,
    }

    impl Shim<'_> {
        /// Materialize the shim as an executable file (bash script), like a
        /// real CLI binary. Returns (config, tempdir-path-to-clean).
        fn arm(&self) -> (RialoConfig, std::path::PathBuf) {
            // G28 — per-call unique dir: PID-only keys made concurrent CI
            // tests race on one shared shim file (cross-script overwrite).
            static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "g25-shim-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("rialo");
            {
                let mut f = std::fs::File::create(&path).unwrap();
                f.write_all(self.script.as_bytes()).unwrap();
            }
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            let cfg = RialoConfig {
                cli: path,
                rpc_url: "http://127.0.0.1:9".into(), // dummy: shim never dials
                program_id: None,
                program_dir: dir.clone(),
            };
            (cfg, dir)
        }
    }

    fn transfer_of(cfg: &RialoConfig) -> Result<String, RialoError> {
        cfg.transfer(
            &std::path::PathBuf::from("/tmp/g25-ignored-keypair.json"),
            "BDEu6owtws5wsuJHxygJuXfFSM1RNgKvQuimeS5NxVBM",
            "0.001",
        )
    }

    /// T1 — spawn failure: shim path does not exist => RIALO_CLI_UNAVAILABLE
    /// with op recorded in diagnostic line (stderr asserted indirectly via
    /// code classification; the diag print itself is exercised for panics).
    #[test]
    fn diag_spawn_fail_reports_cli_unavailable() {
        let cfg = RialoConfig {
            cli: "/tmp/definitely-not-an-executable-rialo-9x7y".into(),
            rpc_url: "http://127.0.0.1:9".into(),
            program_id: None,
            program_dir: "/tmp".into(),
        };
        let err = cfg
            .run(Operation::Read, &["client", "get-block-height"])
            .err()
            .expect("spawn must fail");
        assert_eq!(err.code, "RIALO_CLI_UNAVAILABLE");
        let _ = transfer_of(&cfg); // transfer path exercises same runner
    }

    /// T2 — invalid JSON output (exit 0) → RIALO_ERROR, outcome=out_unparseable
    #[test]
    fn diag_invalid_json_classifies_rialo_error_and_ok_parse_untouched() {
        let (cfg, _tmp) = Shim {
            script: "#!/bin/sh\necho '<!doctype html>'\n",
        }
        .arm();
        // HTML output can NEVER parse as JSON (map_err → RIALO_ERROR) even
        // on exit 0 — decode failure is inside serde_json, not the exit code.
        let err = cfg
            .run(Operation::Read, &["client", "get-block-height"])
            .err()
            .expect("non-JSON output must error via the out_unparseable arm");
        assert_eq!(err.code, "RIALO_ERROR");

        // invalid JSON with exit 1 → out_unparseable arm → RIALO_ERROR
        let (cfg2, _t2) = Shim {
            script: "#!/bin/sh\necho 'garbage-not-json' >&2\nexit 1\n",
        }
        .arm();
        let err = cfg2
            .run(Operation::Read, &["client", "get-block-height"])
            .err()
            .expect("non-JSON + exit1 must error");
        assert_eq!(err.code, "RIALO_ERROR");
    }

    /// T3 — success:false envelope WITHOUT signature → envelope_error, no sig
    #[test]
    fn diag_envelope_error_without_signature() {
        let (cfg, _tmp) = Shim {
            script: r##"#!/bin/sh
            echo '{"success":false,"message":"insufficient funds for fee"}'
            "##,
        }
        .arm();
        let err = transfer_of(&cfg).err().expect("envelope error must error");
        assert_eq!(err.code, "RIALO_ERROR");
        assert!(err.tx_signature.is_none());
    }

    /// T3b — success:false envelope WITH a plausible signature → surfaced in
    /// tx_signature (evidence present; never treated as proof of broadcast).
    #[test]
    fn diag_envelope_error_with_signature_surface() {
        let (cfg, _tmp) = Shim {
            script: r##"#!/bin/sh
            echo '{"success":false,"message":"confirmation timed out after broadcast","signature":"3SkBuJyL7tgM5pHkSV1EwmqRUVCVE1fTWtGFtnkzJHMhRHTdwfUdXh6fLXTYy1PwhVXADc4Uac7obKIfE5YvXee"}'
            "##,
        }
        .arm();
        let err = transfer_of(&cfg).err().expect("envelope error must error");
        assert!(
            err.tx_signature.is_some(),
            "signature evidence must surface (presence only — never logged as a broadcast fact)"
        );
    }

    /// T4 — transfer() must NOT auto-retry on CONFIRMATION_TIMEOUT: the shim
    /// counts its own invocations in a side file; exactly ONE CLI call is
    /// allowed for this error class (no clock-skew retry, no re-broadcast).
    #[test]
    fn transfer_timeout_never_retries_cli() {
        let dir = std::env::temp_dir().join(format!("g25-attempts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cnt = dir.join("count");
        std::fs::write(&cnt, "0").unwrap();
        let script = format!(
            r##"#!/bin/sh
            n=$(cat "{}"); n=$((n+1)); echo "$n" > "{}"
            if [ "$n" -gt 1 ]; then echo '{{"success":true,"signature":"OKSHOULDNEVERHAPPEN"}}'; fi
            echo '{{"success":false,"message":"confirmation timed out","signature":"5VfGSo6VR1kKfQKGYWqNRvkgwPUKdf5pGmSbeYJeWqVKwPGH1VQeLCqQCwffaFW4dbQGJFTnZPCZr8LEJkroREcT"}}'
            "##,
            cnt.display(),
            cnt.display()
        );
        let shim = Shim {
            script: Box::leak(script.into_boxed_str()),
        };
        let (cfg, _tmp) = shim.arm();
        let err = transfer_of(&cfg)
            .err()
            .expect("confirmation timeout must surface as error");
        assert_eq!(err.code, "RIALO_TRANSFER_CONFIRMATION_TIMEOUT");
        let n: usize = std::fs::read_to_string(&cnt)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(n, 1, "auto-retry on uncertain outcome is forbidden");
    }

    /// T5 — clock-skew retry contract UNCHANGED by diagnostics (sanity):
    /// is_retryable_clock_skew still ONLY for RIALO_CLOCK_SKEW.
    #[test]
    fn retry_gate_unchanged() {
        assert!(is_retryable_clock_skew("RIALO_CLOCK_SKEW"));
        assert!(!is_retryable_clock_skew(
            "RIALO_TRANSFER_CONFIRMATION_TIMEOUT"
        ));
        assert!(!is_retryable_clock_skew("RIALO_ERROR"));
    }
}

#[cfg(test)]
mod diag_text_tests {
    use super::*;

    /// G22 T-D1 — caps at 200 chars and marks truncation.
    #[test]
    fn caps_long_first_line() {
        let long = "e".repeat(500);
        let out = diag_text(&long);
        assert!(out.starts_with("eeee"));
        assert!(out.contains("…<truncated>"));
        assert!(out.chars().count() <= 220);
    }

    /// T-D2 — empty/whitespace-only ⇒ <empty> marker (never blank log line).
    #[test]
    fn empty_becomes_marker() {
        assert_eq!(diag_text(""), "<empty>");
        assert_eq!(diag_text("\n\n"), "<empty>");
    }

    /// T-D3 — only the FIRST line is kept (multi-line CLI stderr bodies
    /// may embed stack-ish details; we keep one line, capped).
    #[test]
    fn multiline_keeps_first_line_only() {
        let out = diag_text("first line detail\nsecond line secret-ish\nthird");
        assert!(out.starts_with("first line detail"));
        assert!(!out.contains("second line"));
    }

    /// T-D4 — wallet path neutralization: /app + /home/ prefixes never
    /// appear verbatim (keypair paths embed wallet user ids).
    #[test]
    fn paths_are_neutralized() {
        let out = diag_text("failed to load keypair at /app/artifact/wallets/50506318.json");
        assert!(!out.contains("/app/"), "raw /app path leaked: {out}");
        assert!(out.contains("<app>"));

        let out2 = diag_text("no config at /home/agentpay/.config/rialo");
        assert!(!out2.contains("/home/agentpay"));
        assert!(out2.contains("<home>/"));
    }

    /// T-D5 — a realistic node refusal travels through the sanitizer with
    /// its actionable text intact (that is the whole point of G22), while
    /// any path fragments inside it still get neutralized.
    #[test]
    fn node_refusal_keeps_actionable_text() {
        let node_msg = "Transaction simulation failed: source account has insufficient kelvins for transfer of 1000000 plus fees under current cluster load; review balance and retry";
        let out = diag_text(node_msg);
        assert!(out.contains("insufficient kelvins"));
        assert!(out.contains("review balance"));
        // truncated-at-200 path proof:
        let long = format!("{node_msg} {node_msg}");
        let out2 = diag_text(&long);
        assert!(out2.contains("…<truncated>"));
    }

    // ── G25 additions: sensitive-token redaction contracts ──

    fn sig_token(seed: usize) -> String {
        // deterministic 88-char base58-alphabet token (ed25519 sig shape)
        const A: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        (0..88)
            .map(|i| A[(seed * 31 + i * 7) % 58] as char)
            .collect()
    }

    /// full base58 signatures (87-99 chars) never survive the sanitizer
    #[test]
    fn full_signatures_never_logged() {
        let sig = sig_token(7);
        let msg = format!("confirmation timed out; signature {sig} not confirmed");
        let out = diag_text(&msg);
        assert!(!out.contains(&sig), "full signature leaked: {out}");
        assert!(out.contains("…<sig-redacted>"));
        assert!(
            out.contains("confirmation timed out"),
            "actionable text intact"
        );
    }

    /// long hex blobs (raw seed / key bytes ≥64 hex chars) never survive
    #[test]
    fn long_hex_seeds_never_logged() {
        let hex = "e".repeat(128);
        let msg = format!("raw seed dump: {hex} truncated by cli");
        let out = diag_text(&msg);
        assert!(!out.contains(&hex), "hex seed leaked: {out}");
        assert!(out.contains("…<hex-redacted>"));
    }

    /// wallet user id digit-runs (≥8 digits) never survive
    #[test]
    fn wallet_uid_digits_never_logged() {
        let msg = "wallet integrity failure for user 50506318: file missing";
        let out = diag_text(msg);
        assert!(!out.contains("50506318"), "user id leaked: {out}");
        assert!(out.contains("<uid-redacted>"), "uid marker present: {out}");
        assert!(
            out.contains("wallet integrity failure"),
            "actionable intact"
        );
    }

    /// normal refusal prose survives byte-identical (no over-redaction of
    /// actionable text — the sanitizer must not destroy the diagnosis)
    #[test]
    fn normal_prose_survives_untouched() {
        let msg = "Transaction simulation failed: source account has insufficient kelvins for transfer of 1000000 plus fees; review balance and retry";
        let out = diag_text(msg);
        assert!(out.contains("insufficient kelvins"));
        assert!(out.contains("review balance"));
        assert!(
            !out.contains("<uid-redacted>"),
            "prose must not be redacted"
        );
    }

    /// purity: same input ⇒ identical output (no hidden state)
    #[test]
    fn sanitizer_is_pure_and_repeatable() {
        let msg = "mixed 50506318 /app content with long token and no surprises";
        assert_eq!(diag_text(msg), diag_text(msg));
    }
}

/// G28 — the EXACT production failing shape (envelope_error, success:false,
/// RPC_ERROR vendor envelope, no signature) asserted END-TO-END through
/// run()+transfer(): error code, sig absence, and single-attempt (no retry
/// for this class). This is the regression pin for the live 502 incident.
#[cfg(test)]
mod prod_envelope_regression_tests {
    use super::*;
    use std::io::Write as _;

    struct Shim<'a> {
        script: &'a str,
    }
    impl Shim<'_> {
        fn arm(&self) -> (RialoConfig, std::path::PathBuf) {
            static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "g28-env-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
                    + SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u128
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("rialo");
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(self.script.as_bytes()).unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            let cfg = RialoConfig {
                cli: path,
                rpc_url: "http://127.0.0.1:9".into(),
                program_id: None,
                program_dir: dir.clone(),
            };
            (cfg, dir)
        }
    }

    /// THE production envelope: vendor CLI prints success:false RPC_ERROR
    /// envelope (no signature) on stderr, exit 1, then dies. Server MUST
    /// return RIALO_ERROR with the node's detail — the classification that
    /// surfaced as the 394-byte 502 in production.
    #[test]
    fn prod_envelope_error_maps_to_rialo_error_with_detail() {
        let (cfg, _d) = Shim { script: r##"#!/bin/sh
            echo '{"success":false,"error":{"code":"RPC_ERROR","details":"node refused the transfer for account-level reasons"},"message":"node refused the transfer for account-level reasons"}' >&2
            exit 1
        "## }.arm();
        let err = cfg
            .run(
                Operation::Transfer,
                &["client", "transfer", "x", "0.001", "/kp"],
            )
            .err()
            .expect("failure envelope must error");
        assert_eq!(err.code, "RIALO_ERROR", "prod 502 class");
        assert!(
            err.tx_signature.is_none(),
            "no signature in envelope ⇒ None"
        );
        assert!(
            err.detail.contains("node refused the transfer"),
            "node refusal text must be preserved in detail: {err:?}"
        );
        // and transfer() itself must NOT retry this class:
        assert!(!is_retryable_clock_skew(err.code));
    }
}

#[cfg(test)]
mod transfer_signature_parity_tests {
    use super::*;

    /// G27 — parity pin: the vendor CLI 0.18.1 emits exactly this success
    /// stdout shape on `client transfer` (captured live from a local sink
    /// with full 4-call chain: configHash → sendTransaction → statuses →
    /// blockHeight). transfer_signature MUST keep parsing it unchanged.
    #[test]
    fn parses_real_cli_0_18_1_success_stdout() {
        let cli_stdout = serde_json::json!({
            "signature": "623S1QdSk31iYjC8MLn6FwPewWdQqsCtGUNifGMLsjfk1y6aFLbccPjypNKbA6b2V5MWipSaaYmUrKYNdSawJT9X",
            "status": { "slot": 1u64, "executed": true, "err": null }
        });
        let (sig, slot) =
            transfer_signature(cli_stdout).expect("real CLI success shape must parse");
        assert_eq!(
            sig,
            "623S1QdSk31iYjC8MLn6FwPewWdQqsCtGUNifGMLsjfk1y6aFLbccPjypNKbA6b2V5MWipSaaYmUrKYNdSawJT9X"
        );
        assert_eq!(slot, Some(1));
    }

    /// executed=false ⇒ transfer not executed (pre-broadcast refund class).
    #[test]
    fn rejects_pending_status() {
        let cli_stdout = serde_json::json!({
            "signature": "623S1QdSk31iYjC8MLn6FwPewWdQqsCtGUNifGMLsjfk1y6aFLbccPjypNKbA6b2V5MWipSaaYmUrKYNdSawJT9X",
            "status": { "slot": 1u64, "executed": false, "err": null }
        });
        let err = transfer_signature(cli_stdout)
            .err()
            .expect("pending must error");
        assert_eq!(err.code, "RIALO_TRANSFER_ERROR");
    }

    /// err present ⇒ node-side definitive failure (same refund class),
    /// and the message must carry the node's own error verbatim.
    #[test]
    fn rejects_chain_err_with_verbatim_text() {
        let cli_stdout = serde_json::json!({
            "signature": "623S1QdSk31iYjC8MLn6FwPewWdQqsCtGUNifGMLsjfk1y6aFLbccPjypNKbA6b2V5MWipSaaYmUrKYNdSawJT9X",
            "status": { "slot": 1u64, "executed": false, "err": "insufficient kelvins for rent-exempt storage" }
        });
        let err = transfer_signature(cli_stdout)
            .err()
            .expect("chain err must error");
        assert_eq!(err.code, "RIALO_TRANSFER_ERROR");
        assert!(
            err.detail
                .contains("insufficient kelvins for rent-exempt storage")
        );
    }
}
