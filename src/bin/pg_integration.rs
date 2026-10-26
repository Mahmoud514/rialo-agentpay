// Disposable PostgreSQL integration tests for the Worker-auth/V8 design.
//
// This binary is test-only. It starts a local embedded PostgreSQL instance,
// never reads DATABASE_URL, and never contacts production. The SQL files are
// copies of the reviewed migration sources; applying them here is allowed only
// on this disposable instance.

#[path = "server/wallet_provisioning.rs"]
mod wallet_provisioning;

fn main() {}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use postgresql_embedded::blocking::PostgreSQL;
    use tokio_postgres::NoTls;

    static URL: OnceLock<String> = OnceLock::new();
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn runtime() -> &'static tokio::runtime::Runtime {
        static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
        RT.get_or_init(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("test runtime")
        })
    }

    fn test_url() -> String {
        URL.get_or_init(|| {
            let mut pg = Box::new(PostgreSQL::default());
            pg.setup().expect("embedded pg setup");
            pg.start().expect("embedded pg start");
            pg.create_database("agentpay_auth_integration")
                .expect("create disposable test db");
            let url = pg.settings().url("agentpay_auth_integration");
            assert!(
                url.contains("localhost") || url.contains("127.0.0.1"),
                "refusing non-local PostgreSQL URL: {url}"
            );
            // Keep the disposable server alive for the whole test binary.
            std::mem::forget(pg);
            url
        })
        .clone()
    }

    fn connect() -> tokio_postgres::Client {
        let url = test_url();
        let rt = runtime();
        rt.block_on(async {
            let (client, connection) = tokio_postgres::connect(&url, NoTls)
                .await
                .expect("connect disposable pg");
            tokio::spawn(async move {
                let _ = connection.await;
            });
            client
        })
    }

    fn base_schema(client: &tokio_postgres::Client) {
        runtime().block_on(async {
            client
                .batch_execute(
                    r#"
                    CREATE TABLE IF NOT EXISTS schema_migrations (
                        version BIGINT PRIMARY KEY,
                        applied_at BIGINT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS tasks_pg (
                        task_id TEXT PRIMARY KEY,
                        status TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS sessions (
                        session_id TEXT PRIMARY KEY,
                        user_id BIGINT NOT NULL,
                        login TEXT NOT NULL,
                        created_at BIGINT NOT NULL,
                        expires_at BIGINT
                    );
                    CREATE TABLE IF NOT EXISTS user_wallets (
                        user_id BIGINT PRIMARY KEY,
                        pubkey TEXT NOT NULL,
                        created_at BIGINT NOT NULL
                    );
                    "#,
                )
                .await
                .expect("base schema");
        });
    }

    fn apply_migration(client: &tokio_postgres::Client, sql: &str) {
        runtime()
            .block_on(async { client.batch_execute(sql).await })
            .expect("migration batch");
    }

    fn reset_v8(client: &tokio_postgres::Client) {
        runtime().block_on(async {
            client
                .batch_execute("TRUNCATE wallet_provision_requests, user_wallets")
                .await
                .expect("reset v8 tables");
        });
    }

    fn claim_sql() -> &'static str {
        r#"
        WITH candidate AS (
            SELECT user_id
            FROM wallet_provision_requests
            WHERE (state = 'pending' AND next_attempt_at <= $1)
               OR (state = 'provisioning' AND lease_until < $1)
            ORDER BY requested_at
            FOR UPDATE SKIP LOCKED
            LIMIT 1
        )
        UPDATE wallet_provision_requests r
        SET state = 'provisioning',
            attempts = r.attempts + 1,
            lease_until = $1 + $2,
            worker_id = $3,
            updated_at = $1
        FROM candidate c
        WHERE r.user_id = c.user_id
        RETURNING r.user_id, r.attempts, r.worker_id
        "#
    }

    fn insert_request(client: &tokio_postgres::Client, user_id: i64, state: &str, next: i64, lease: Option<i64>, worker: Option<&str>) {
        runtime().block_on(async {
            client
                .execute(
                    "INSERT INTO wallet_provision_requests
                       (user_id, state, attempts, next_attempt_at, lease_until, worker_id,
                        last_error_code, requested_at, updated_at)
                     VALUES ($1,$2,0,$3,$4,$5,NULL,100,100)",
                    &[&user_id, &state, &next, &lease, &worker],
                )
                .await
                .expect("insert request");
        });
    }

    #[test]
    fn migrations_v6_v7_v8_apply_twice_and_preserve_rows() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let client = connect();
        base_schema(&client);

        // Existing rows that must survive additive migrations.
        runtime().block_on(async {
            client
                .execute(
                    "INSERT INTO tasks_pg (task_id, status) VALUES ('legacy-task', 'open')",
                    &[],
                )
                .await
                .expect("seed task");
            client
                .execute(
                    "INSERT INTO sessions (session_id, user_id, login, created_at, expires_at)
                     VALUES ('legacy-session', 7, 'legacy', 100, NULL)",
                    &[],
                )
                .await
                .expect("seed session");
        });

        // Exact reviewed sources, in order, then reapply each one.
        let v6 = include_str!("../../migrations/0006_fair_review.sql");
        let v7 = include_str!("../../migrations/0007_worker_auth.sql");
        let v8 = include_str!("../../migrations/0008_wallet_provisioning.sql");
        for sql in [v6, v7, v8] {
            apply_migration(&client, sql);
            apply_migration(&client, sql);
        }

        runtime().block_on(async {
            let versions: Vec<i64> = client
                .query(
                    "SELECT version FROM schema_migrations WHERE version IN (6,7,8) ORDER BY version",
                    &[],
                )
                .await
                .expect("versions")
                .iter()
                .map(|row| row.get(0))
                .collect();
            assert_eq!(versions, vec![6, 7, 8]);

            let task_count: i64 = client
                .query_one("SELECT count(*) FROM tasks_pg WHERE task_id = 'legacy-task'", &[])
                .await
                .expect("task count")
                .get(0);
            assert_eq!(task_count, 1);
            let session_count: i64 = client
                .query_one(
                    "SELECT count(*) FROM sessions WHERE session_id = 'legacy-session'",
                    &[],
                )
                .await
                .expect("session count")
                .get(0);
            assert_eq!(session_count, 1);

            let columns: Vec<String> = client
                .query(
                    "SELECT column_name FROM information_schema.columns
                     WHERE table_name = 'wallet_provision_requests'",
                    &[],
                )
                .await
                .expect("columns")
                .iter()
                .map(|row| row.get(0))
                .collect();
            for forbidden in ["private", "secret", "seed", "key", "signature"] {
                assert!(
                    columns.iter().all(|column| !column.to_ascii_lowercase().contains(forbidden)),
                    "forbidden column {forbidden:?} in outbox"
                );
            }
        });
    }

    #[test]
    fn pg_provision_store_adapter_enqueues_claims_and_fences_stale_worker() {
        use super::wallet_provisioning::ProvisionStore;
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let schema_client = connect();
        base_schema(&schema_client);
        apply_migration(&schema_client, include_str!("../../migrations/0008_wallet_provisioning.sql"));
        reset_v8(&schema_client);

        // A dedicated runtime owns both connections; the synchronous adapter
        // is exercised from a normal test thread, not from inside its runtime.
        let rt = std::sync::Arc::new(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("adapter runtime"),
        );
        let (client, connection) = rt
            .block_on(tokio_postgres::connect(&test_url(), NoTls))
            .expect("adapter connect");
        rt.spawn(connection);
        let (observer, observer_connection) = rt
            .block_on(tokio_postgres::connect(&test_url(), NoTls))
            .expect("observer connect");
        rt.spawn(observer_connection);

        let store = super::wallet_provisioning::PgProvisionStore::new(
            std::sync::Arc::new(client),
            rt.clone(),
        );
        assert_eq!(
            store.enqueue(7, 100),
            Ok(super::wallet_provisioning::EnqueueOutcome::Created)
        );
        assert_eq!(
            store.enqueue(7, 101),
            Ok(super::wallet_provisioning::EnqueueOutcome::AlreadyPresent)
        );
        assert!(!store.wallet_exists(7).unwrap());

        let first = store.claim("worker-a", 100, 10).unwrap().unwrap();
        assert_eq!(first.user_id, 7);
        assert!(store.claim("worker-b", 105, 10).unwrap().is_none());

        // At lease expiry worker-b takes over; worker-a must not commit.
        let second = store.claim("worker-b", 111, 10).unwrap().unwrap();
        assert_eq!(second.user_id, 7);
        assert_eq!(second.attempts, 2);

        // No public registry row yet: even the lease owner cannot mark ready.
        assert!(store.mark_ready(7, 112, "worker-b").is_err());
        rt.block_on(observer.execute(
            "INSERT INTO user_wallets (user_id, pubkey, created_at) VALUES (7, 'pubkey-7', 100)
             ON CONFLICT (user_id) DO NOTHING",
            &[],
        ))
        .unwrap();

        // At lease expiry worker-b took over; worker-a must not commit.
        assert!(store.mark_ready(7, 112, "worker-a").is_err());
        let state: String = rt
            .block_on(observer.query_one(
                "SELECT state, worker_id FROM wallet_provision_requests WHERE user_id=7",
                &[],
            ))
            .unwrap()
            .get(0);
        assert_eq!(state, "provisioning");
        store.mark_ready(7, 112, "worker-b").unwrap();
        let state: String = rt
            .block_on(observer.query_one(
                "SELECT state FROM wallet_provision_requests WHERE user_id=7",
                &[],
            ))
            .unwrap()
            .get(0);
        assert_eq!(state, "ready");
    }

    #[test]
    fn pg_provision_store_disconnect_is_typed_and_does_not_mark_ready() {
        use super::wallet_provisioning::ProvisionStore;
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let rt = std::sync::Arc::new(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("disconnected adapter runtime"),
        );
        let (client, connection) = rt
            .block_on(tokio_postgres::connect(&test_url(), NoTls))
            .expect("disconnect test connect");
        // Drop the driver without spawning it: the client is closed.
        drop(connection);
        let store = super::wallet_provisioning::PgProvisionStore::new(
            std::sync::Arc::new(client),
            rt.clone(),
        );
        assert!(store.enqueue(44, 100).is_err());
        assert!(store.claim("worker-a", 100, 10).is_err());
        assert!(store.mark_ready(44, 101, "worker-a").is_err());
    }

    #[test]
    #[ignore = "BLOCKED: signer v2 POST /user/wallet requires operator generation/admin ceremony secrets, a registered auth binding, creation-intent signature and signer-side gate; no safe app-side adapter exists"]
    fn v8_isolated_signer_v2_user_wallet_adapter_is_blocked() {
        // This test is intentionally not a green substitute. It records the
        // missing contract so no future change silently claims v2 integration.
        panic!("V8 v2 adapter is blocked: see design/g1155-v8-signer-boundary.md");
    }

    #[test]
    fn v8_concurrent_claim_and_idempotent_enqueue() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let c1 = connect();
        let c2 = connect();
        base_schema(&c1);
        reset_v8(&c1);

        // Idempotent enqueue: two INSERTs, one row.
        runtime().block_on(async {
            for _ in 0..2 {
                c1.execute(
                    "INSERT INTO wallet_provision_requests
                       (user_id, state, attempts, next_attempt_at, requested_at, updated_at)
                     VALUES (1,'pending',0,100,100,100)
                     ON CONFLICT (user_id) DO NOTHING",
                    &[],
                )
                .await
                .expect("enqueue");
            }
            let count: i64 = c1
                .query_one("SELECT count(*) FROM wallet_provision_requests", &[])
                .await
                .expect("count")
                .get(0);
            assert_eq!(count, 1);
        });

        // Two independent connections race for the same row.
        let (r1, r2) = runtime().block_on(async {
            tokio::join!(
                c1.query(claim_sql(), &[&100_i64, &50_i64, &"worker-a"]),
                c2.query(claim_sql(), &[&100_i64, &50_i64, &"worker-b"])
            )
        });
        let r1 = r1.expect("claim a");
        let r2 = r2.expect("claim b");
        assert_eq!(r1.len() + r2.len(), 1, "exactly one worker must claim");
        let row = runtime().block_on(c1.query_one(
            "SELECT state, attempts, worker_id FROM wallet_provision_requests WHERE user_id=1",
            &[],
        )).expect("claim row");
        assert_eq!(row.get::<_, String>(0), "provisioning");
        assert!(row.get::<_, i32>(1) >= 1);
        assert!(row.get::<_, Option<String>>(2).is_some());
    }

    #[test]
    fn v8_lease_takeover_blocks_stale_worker() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let c1 = connect();
        let c2 = connect();
        base_schema(&c1);
        reset_v8(&c1);
        insert_request(&c1, 2, "provisioning", 100, Some(100), Some("old-worker"));

        runtime().block_on(async {
            let claimed = c2
                .query(claim_sql(), &[&101_i64, &50_i64, &"new-worker"])
                .await
                .expect("takeover claim");
            assert_eq!(claimed.len(), 1);
            assert_eq!(claimed[0].get::<_, String>(2), "new-worker");

            let stale = c1
                .execute(
                    "UPDATE wallet_provision_requests
                     SET state='ready', updated_at=102
                     WHERE user_id=2 AND state='provisioning' AND worker_id=$1",
                    &[&"old-worker"],
                )
                .await
                .expect("stale update");
            assert_eq!(stale, 0, "old worker must not commit after takeover");

            let current = c2
                .execute(
                    "UPDATE wallet_provision_requests
                     SET state='ready', updated_at=102
                     WHERE user_id=2 AND state='provisioning' AND worker_id=$1",
                    &[&"new-worker"],
                )
                .await
                .expect("new update");
            assert_eq!(current, 1);
        });
    }

    #[test]
    fn v8_advisory_lock_prevents_duplicate_provisioning_when_lease_expires() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let c1 = connect();
        let c2 = connect();
        base_schema(&c1);
        reset_v8(&c1);
        insert_request(&c1, 3, "provisioning", 100, Some(100), Some("signer-a"));

        runtime().block_on(async {
            let key = "wallet-provision:3";
            let a: bool = c1
                .query_one("SELECT pg_try_advisory_lock(hashtext($1)::bigint)", &[&key])
                .await
                .expect("lock a")
                .get(0);
            assert!(a, "first signer must acquire the provisioning lock");

            // Lease has expired, so another claimant can select the row, but
            // it must not enter the signer while the advisory lock is held.
            let claimed = c2
                .query(claim_sql(), &[&101_i64, &50_i64, &"signer-b"])
                .await
                .expect("expired lease claim");
            assert_eq!(claimed.len(), 1);

            let b: bool = c2
                .query_one("SELECT pg_try_advisory_lock(hashtext($1)::bigint)", &[&key])
                .await
                .expect("lock b")
                .get(0);
            assert!(!b, "second signer must be excluded by the advisory lock");

            let released: bool = c1
                .query_one("SELECT pg_advisory_unlock(hashtext($1)::bigint)", &[&key])
                .await
                .expect("unlock a")
                .get(0);
            assert!(released);
        });
    }

    #[test]
    fn v8_retry_backoff_and_existing_wallet() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let c1 = connect();
        base_schema(&c1);
        reset_v8(&c1);
        insert_request(&c1, 4, "pending", 300, None, None);

        runtime().block_on(async {
            let before = c1
                .query(claim_sql(), &[&299_i64, &50_i64, &"worker-a"])
                .await
                .expect("before backoff");
            assert_eq!(before.len(), 0);
            let at = c1
                .query(claim_sql(), &[&300_i64, &50_i64, &"worker-a"])
                .await
                .expect("at backoff");
            assert_eq!(at.len(), 1);

            c1.execute(
                "INSERT INTO user_wallets (user_id, pubkey, created_at)
                 VALUES (5, 'PUBLIC_ONLY', 100)",
                &[],
            )
            .await
            .expect("existing wallet");
            c1.execute(
                "INSERT INTO wallet_provision_requests
                   (user_id, state, attempts, next_attempt_at, requested_at, updated_at)
                 VALUES (5,'pending',0,100,100,100)",
                &[],
            )
            .await
            .expect("existing request");
            let exists: bool = c1
                .query_one(
                    "SELECT EXISTS (SELECT 1 FROM user_wallets WHERE user_id=5)",
                    &[],
                )
                .await
                .expect("wallet exists")
                .get(0);
            assert!(exists, "existing wallet must be detected before minting");
            c1.execute(
                "UPDATE wallet_provision_requests SET state='ready' WHERE user_id=5",
                &[],
            )
            .await
            .expect("mark existing wallet ready");

            // A registered-but-missing wallet must remain a terminal failure;
            // the outbox has no replacement-wallet operation.
            c1.execute(
                "INSERT INTO wallet_provision_requests
                   (user_id, state, attempts, next_attempt_at, requested_at, updated_at)
                 VALUES (6,'wallet_missing',0,100,100,100)",
                &[],
            )
            .await
            .expect("missing wallet row");
            let missing_claim = c1
                .query(claim_sql(), &[&300_i64, &50_i64, &"worker-a"])
                .await
                .expect("missing wallet must not be claimed");
            assert_eq!(missing_claim.len(), 0);
            let missing_state: String = c1
                .query_one(
                    "SELECT state FROM wallet_provision_requests WHERE user_id=6",
                    &[],
                )
                .await
                .expect("missing state")
                .get(0);
            assert_eq!(missing_state, "wallet_missing");
            let replacement: i64 = c1
                .query_one(
                    "SELECT count(*) FROM user_wallets WHERE user_id=6",
                    &[],
                )
                .await
                .expect("no replacement wallet")
                .get(0);
            assert_eq!(replacement, 0);
        });
    }
}
