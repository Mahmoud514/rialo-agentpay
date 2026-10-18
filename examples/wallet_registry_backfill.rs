//! G21.12.6 — Wallet Registry Backfill Tool (Dry-Run by default).
//!
//! Scans legacy FS wallet files (`artifact/wallets/<github_id>.json`),
//! derives ONLY the public key from each valid file, and upserts the
//! pubkey into the PostgreSQL `user_wallets` registry. Private keys and
//! seeds are NEVER printed, logged, or written to PostgreSQL.
//!
//! Safety contract:
//! - DEFAULT IS DRY-RUN. No DB write happens without an explicit
//!   `--write` flag AND a working `--database-url` (or DATABASE_URL env).
//! - Dormant without `--wallet-dir` (prints usage/plan and exits 0 when
//!   no scan root is provided).
//! - Never replaces an existing registry row with a different pubkey
//!   (identity conflict → counted as CONFLICT, no write).
//! - Never creates wallets or key material; a missing file is only
//!   REPORTED (MISSING), never regenerated.
//! - Idempotent: re-running on the same data converges; already-matching
//!   rows are counted MATCH and skipped.
//! - Summary counts never contain secrets (only per-class tallies and
//!   anonymized user ids).
//!
//! Read the database URL from `--database-url` or `DATABASE_URL`. Use a
//! dedicated test database for rehearsal; never run `--write` against
//! production without a separate owner approval.
//!
//! Usage:
//!   cargo run --example wallet_registry_backfill -- [--wallet-dir DIR] \
//!       [--database-url URL] [--write] [--json]
//!
//! Classification buckets:
//!   OK            — valid file, no registry row  → would insert (or inserted with --write)
//!   MATCH         — valid file, registry row equals derived pubkey (no-op)
//!   CONFLICT      — valid file, registry row holds a DIFFERENT pubkey (no-write, reported)
//!   CORRUPT       — file exists but cannot be parsed as a keypair
//!   MISSING       — registry has a row for an id whose file is missing (report-only;
//!                   also covers ids discovered in DB absent on disk during a scan)
//!   DB_ERROR      — registry read/write failure (connection refusal, etc.)

use rialo_s_signer::Signer;
use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};

/// A derived public key from a legacy wallet file.
///
/// The file stores a JSON keypair; we MUST NOT log or store any private
/// material. We read the file purely to derive the account id via the
/// same keypair-parsing surface the server uses.
///
/// IMPORTANT: to guarantee no secret ever reaches stdout/logs, the
/// keypair parsing happens through `rialo_s_keypair::read_keypair` and we
/// keep only the string form of the public key. Derivation never touches
/// the secret bytes beyond the parser's own memory.
#[derive(Debug)]
enum Classification {
    /// Valid file, and this is its derived public key.
    Ok(String),
    /// File exists but is unreadable/corrupt.
    Corrupt,
}

fn derive_pubkey(path: &Path) -> Classification {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => return Classification::Corrupt,
    };
    // Parse with the same keypair crate the server uses; private key never
    // leaves this function; only the pubkey string escapes.
    let mut cursor = std::io::Cursor::new(bytes);
    match rialo_s_keypair::read_keypair(&mut cursor) {
        Ok(kp) => Classification::Ok(kp.pubkey().to_string()),
        Err(_) => Classification::Corrupt,
    }
}

fn main() {
    let mut wallet_dir: Option<PathBuf> = None;
    let mut database_url: Option<String> = None;
    let mut write_mode = false;
    let mut json_output = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--wallet-dir" => {
                wallet_dir = args.next().map(PathBuf::from);
            }
            "--database-url" => {
                database_url = args.next();
            }
            "--write" => write_mode = true,
            "--json" => json_output = true,
            other => {
                eprintln!("unknown argument: {other}");
                eprintln!(
                    "usage: cargo run --example wallet_registry_backfill -- \
                     [--wallet-dir DIR] [--database-url URL] [--write] [--json]"
                );
                std::process::exit(2);
            }
        }
    }

    let Some(scan_dir) = wallet_dir else {
        eprintln!(
            "DRY-RUN tool. Provide --wallet-dir to scan; \
             add --database-url (or DATABASE_URL) and --write to actually insert rows."
        );
        eprintln!("Nothing was done. Exiting.");
        return;
    };

    // ---- Phase 1: scan filesystem --------------------------------------
    // Map<user_id, (derived pubkey | corrupt)>
    let mut on_disk: BTreeMap<u64, Classification> = BTreeMap::new();
    let entries = match std::fs::read_dir(&scan_dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("cannot read wallet dir {scan_dir:?}: {e}");
            std::process::exit(1);
        }
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(stem) = name.strip_suffix(".json") else {
            continue;
        };
        let Ok(user_id) = stem.parse::<u64>() else {
            // Not a user-wallet file naming scheme; skip silently.
            continue;
        };
        let class = derive_pubkey(&entry.path());
        on_disk.insert(user_id, class);
    }

    // ---- Phase 2: ensure DB connectivity (only when writing is intended)
    let url = database_url.or_else(|| std::env::var("DATABASE_URL").ok());
    if write_mode && url.is_none() {
        eprintln!("--write requires --database-url or DATABASE_URL");
        std::process::exit(2);
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("backfill runtime");
    let connected = match url.as_deref() {
        Some(u) => match rt.block_on(tokio_postgres::connect(u, tokio_postgres::NoTls)) {
            Ok((c, conn)) => {
                std::thread::spawn(move || {
                    let rt2 = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("conn runtime");
                    let _ = rt2.block_on(conn);
                });
                Some(c)
            }
            Err(e) => {
                eprintln!("database connect failed (treating as DB outage): {e}");
                None
            }
        },
        None => None,
    };

    // ---- Phase 3: classify against the registry -------------------------
    let mut stats = BTreeMap::from([
        ("ok_to_migrate", 0u64),
        ("match_already_registered", 0u64),
        ("conflict_identity", 0u64),
        ("corrupt_file", 0u64),
        ("missing_file", 0u64),
        ("db_error", 0u64),
        ("inserted", 0u64),
    ]);
    let mut details: Vec<String> = Vec::new();
    let inserted_rows: std::sync::Mutex<Vec<(u64, String)>> = std::sync::Mutex::new(Vec::new());

    let pg_alive = connected.is_some();
    for (user_id, class) in &on_disk {
        match class {
            Classification::Corrupt => {
                *stats.get_mut("corrupt_file").unwrap() += 1;
                details.push(format!("CORRUPT user={user_id}"));
            }
            Classification::Ok(pubkey) => {
                let row: Option<String> = match connected.as_ref() {
                    Some(c) => match rt.block_on(c.query_opt(
                        "SELECT pubkey FROM user_wallets WHERE user_id = $1",
                        &[&(*user_id as i64)],
                    )) {
                        Ok(r) => r.map(|row| row.get(0)),
                        Err(e) => {
                            *stats.get_mut("db_error").unwrap() += 1;
                            details.push(format!("DB_ERROR user={user_id} read: {e}"));
                            continue;
                        }
                    },
                    None => None,
                };
                match row {
                    Some(stored) if stored == *pubkey => {
                        *stats.get_mut("match_already_registered").unwrap() += 1;
                        details.push(format!("MATCH user={user_id}"));
                    }
                    Some(stored) => {
                        *stats.get_mut("conflict_identity").unwrap() += 1;
                        // Never print either pubkey in full in conflict
                        // details? We DO print the file pubkey: it is
                        // public (an on-chain address). Registry pubkey is
                        // public too. But keep the summary conservative:
                        // only user id is printed for CONFLICT.
                        details.push(format!(
                            "CONFLICT user={user_id} (registry holds a different pubkey; no write)"
                        ));
                        let _ = stored;
                    }
                    None => {
                        *stats.get_mut("ok_to_migrate").unwrap() += 1;
                        if write_mode && !pg_alive {
                            *stats.get_mut("db_error").unwrap() += 1;
                            details.push(format!(
                                "DB_ERROR user={user_id} write requested but database is unreachable"
                            ));
                        } else if write_mode {
                            match rt.block_on(spawn_insert(
                                connected.as_ref().unwrap(),
                                *user_id,
                                pubkey,
                            )) {
                                Ok(()) => {
                                    *stats.get_mut("inserted").unwrap() += 1;
                                    details.push(format!("INSERTED user={user_id}"));
                                    inserted_rows
                                        .lock()
                                        .unwrap()
                                        .push((*user_id, pubkey.clone()));
                                }
                                Err(e) => {
                                    *stats.get_mut("db_error").unwrap() += 1;
                                    details.push(format!("DB_ERROR user={user_id} insert: {e}"));
                                }
                            }
                        } else {
                            details.push(format!("OK user={user_id} (dry-run; would insert)"));
                        }
                    }
                }
            }
        }
    }

    // ---- Phase 4: DB-side sweep for registered-but-file-missing --------
    // When connected, enumerate registry ids and mark those without a
    // file on disk as MISSING (report-only, "regenerate nothing").
    if pg_alive {
        let rows = match rt.block_on(
            connected
                .as_ref()
                .unwrap()
                .query("SELECT user_id FROM user_wallets", &[]),
        ) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("registry sweep failed: {e}");
                rows_placeholder()
            }
        };
        for row in rows {
            let db_id: i64 = row.get(0);
            let id = db_id.unsigned_abs();
            if !on_disk.contains_key(&id) {
                *stats.get_mut("missing_file").unwrap() += 1;
                details.push(format!(
                    "MISSING user={id} (registered without file; do NOT regenerate)"
                ));
            }
        }
    }

    // ---- Phase 5: summary (no secrets) ----------------------------------
    // G21.12.8: in --write mode, DB errors and identity conflicts are hard
    // failures: the full report still prints, but the process exits
    // non-zero so automation never mistakes a partial run for success.
    // Dry-runs always exit 0 (they never write).
    let hard_failures: u64 = if write_mode {
        stats["db_error"] + stats["conflict_identity"]
    } else {
        0
    };
    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "mode": if write_mode { "WRITE" } else { "DRY-RUN" },
                "database_connected": pg_alive,
                "files_scanned": on_disk.len(),
                "ok_to_migrate": stats["ok_to_migrate"],
                "match_already_registered": stats["match_already_registered"],
                "conflict_identity": stats["conflict_identity"],
                "corrupt_file": stats["corrupt_file"],
                "missing_file": stats["missing_file"],
                "db_error": stats["db_error"],
                "inserted": stats["inserted"],
            })
        );
    } else {
        println!(
            "==== Wallet Registry Backfill — {} ====",
            if write_mode { "WRITE" } else { "DRY-RUN" }
        );
        println!("files_scanned: {}", on_disk.len());
        println!("ok_to_migrate: {}", stats["ok_to_migrate"]);
        println!(
            "match_already_registered: {}",
            stats["match_already_registered"]
        );
        println!("conflict_identity: {}", stats["conflict_identity"]);
        println!("corrupt_file: {}", stats["corrupt_file"]);
        println!("missing_file: {}", stats["missing_file"]);
        println!("db_error: {}", stats["db_error"]);
        println!("inserted: {}", stats["inserted"]);
        println!("---- details (user ids only; no keys, no file contents) ----");
        for d in &details {
            println!("{d}");
        }
    }

    // Guard: in dry-run we must not have inserted anything.
    debug_assert!(write_mode || inserted_rows.lock().unwrap().is_empty());

    if hard_failures > 0 {
        eprintln!(
            "FAILED: {hard_failures} hard failure(s) in --write mode (db_error + identity conflicts); see report above."
        );
        std::process::exit(1);
    }
}

fn rows_placeholder() -> Vec<tokio_postgres::Row> {
    Vec::new()
}

/// Race-safe without `&mut Client`: ON CONFLICT DO NOTHING can never
/// overwrite an existing row; after the insert we re-read the stored
/// pubkey to detect a lost race (a different key already present).
fn spawn_insert<'a>(
    client: &'a tokio_postgres::Client,
    user_id: u64,
    pubkey: &'a str,
) -> impl Future<Output = Result<(), String>> + 'a {
    async move {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        client
            .execute(
                "INSERT INTO user_wallets (user_id, pubkey, created_at) VALUES ($1, $2, $3) ON CONFLICT (user_id) DO NOTHING",
                &[&(user_id as i64), &pubkey, &now],
            )
            .await
            .map_err(|e| e.to_string())?;
        let row = client
            .query_opt(
                "SELECT pubkey FROM user_wallets WHERE user_id = $1",
                &[&(user_id as i64)],
            )
            .await
            .map_err(|e| e.to_string())?;
        match row {
            Some(r) if r.get::<_, String>(0) == pubkey => Ok(()),
            Some(_) => Err("identity-conflict-on-write".into()),
            None => Err("insert vanished".into()),
        }
    }
}
