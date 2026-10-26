//! Stage 3 — wallet provisioning outbox.
//!
//! This module models the signer-side workflow. It never creates, reads,
//! logs, or stores private key material. The actual key operation remains the
//! existing signer/Blitz code path (`strict_wallet_load_or_mint` /
//! `load_wallet_strict`), invoked through the `ProvisionSigner` trait.
//!
//! G1154 adds an opt-in worker in the server binary
//! (`AGENTPAY_WALLET_PROVISIONING=1`) and a best-effort enqueue from the
//! Worker auth login/link flow. The module itself stays reusable by the
//! pg_integration test binary and does not reference server-only parents.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

pub const MAX_ATTEMPTS: u32 = 5;
pub const LEASE_SECONDS: i64 = 120;
pub const BACKOFF_BASE_SECONDS: i64 = 5;
pub const BACKOFF_MAX_SECONDS: i64 = 300;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProvisionState {
    Pending,
    Provisioning,
    Ready,
    Failed,
    WalletMissing,
}

impl ProvisionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Provisioning => "provisioning",
            Self::Ready => "ready",
            Self::Failed => "failed",
            Self::WalletMissing => "wallet_missing",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureClass {
    /// Retryable (DB/transient signer availability). Never a key error.
    Transient,
    /// A registered wallet is missing/corrupt or has an identity mismatch.
    /// Requires explicit operator recovery; never mint a replacement.
    WalletMissing,
    /// Non-retryable, non-key failure; requires explicit intervention.
    Permanent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignerError {
    pub class: FailureClass,
    /// Static code only. Never include private key material, seed phrases,
    /// wallet file contents, signatures, paths, or raw signer errors.
    pub code: &'static str,
}

impl SignerError {
    pub const fn new(class: FailureClass, code: &'static str) -> Self {
        Self { class, code }
    }

    pub const fn transient(code: &'static str) -> Self {
        Self::new(FailureClass::Transient, code)
    }

    pub const fn wallet_missing(code: &'static str) -> Self {
        Self::new(FailureClass::WalletMissing, code)
    }

    pub const fn permanent(code: &'static str) -> Self {
        Self::new(FailureClass::Permanent, code)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnqueueOutcome {
    Created,
    AlreadyPresent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionTask {
    pub user_id: u64,
    pub attempts: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Processed {
    ReadyExistingWallet,
    ReadyProvisioned,
    RetryScheduled,
    Failed,
    WalletMissing,
    NoWork,
}

pub trait ProvisionStore {
    fn enqueue(&self, user_id: u64, now: i64) -> Result<EnqueueOutcome, StoreError>;
    fn wallet_exists(&self, user_id: u64) -> Result<bool, StoreError>;
    fn claim(&self, worker_id: &str, now: i64, lease_seconds: i64)
        -> Result<Option<ProvisionTask>, StoreError>;
    fn mark_ready(&self, user_id: u64, now: i64, worker_id: &str) -> Result<(), StoreError>;
    fn reschedule(
        &self,
        user_id: u64,
        now: i64,
        next_attempt_at: i64,
        error_code: &'static str,
        worker_id: &str,
    ) -> Result<(), StoreError>;
    fn mark_failed(
        &self,
        user_id: u64,
        now: i64,
        state: ProvisionState,
        error_code: &'static str,
        worker_id: &str,
    ) -> Result<(), StoreError>;
}

pub trait ProvisionSigner {
    /// Ensure exactly one signer-side wallet for `user_id`.
    ///
    /// Implementations MUST use the existing strict load/mint behavior:
    /// - existing registered wallet: load only, never mint a replacement;
    /// - registered-but-missing/corrupt: return `WalletMissing`;
    /// - no registered wallet: mint/register once;
    /// - no private material leaves the signer.
    fn ensure_wallet(&self, user_id: u64) -> Result<(), SignerError>;
}

impl<T: ProvisionSigner + ?Sized> ProvisionSigner for &T {
    fn ensure_wallet(&self, user_id: u64) -> Result<(), SignerError> {
        (**self).ensure_wallet(user_id)
    }
}

impl<T: ProvisionSigner + ?Sized> ProvisionSigner for std::sync::Arc<T> {
    fn ensure_wallet(&self, user_id: u64) -> Result<(), SignerError> {
        (**self).ensure_wallet(user_id)
    }
}

impl<T: ProvisionStore + ?Sized> ProvisionStore for &T {
    fn enqueue(&self, user_id: u64, now: i64) -> Result<EnqueueOutcome, StoreError> {
        (**self).enqueue(user_id, now)
    }

    fn wallet_exists(&self, user_id: u64) -> Result<bool, StoreError> {
        (**self).wallet_exists(user_id)
    }

    fn claim(
        &self,
        worker_id: &str,
        now: i64,
        lease_seconds: i64,
    ) -> Result<Option<ProvisionTask>, StoreError> {
        (**self).claim(worker_id, now, lease_seconds)
    }

    fn mark_ready(&self, user_id: u64, now: i64, worker_id: &str) -> Result<(), StoreError> {
        (**self).mark_ready(user_id, now, worker_id)
    }

    fn reschedule(
        &self,
        user_id: u64,
        now: i64,
        next_attempt_at: i64,
        error_code: &'static str,
        worker_id: &str,
    ) -> Result<(), StoreError> {
        (**self).reschedule(user_id, now, next_attempt_at, error_code, worker_id)
    }

    fn mark_failed(
        &self,
        user_id: u64,
        now: i64,
        state: ProvisionState,
        error_code: &'static str,
        worker_id: &str,
    ) -> Result<(), StoreError> {
        (**self).mark_failed(user_id, now, state, error_code, worker_id)
    }
}

pub struct Provisioner<S, O> {
    signer: S,
    store: O,
}

impl<S: ProvisionSigner, O: ProvisionStore> Provisioner<S, O> {
    pub fn new(signer: S, store: O) -> Self {
        Self { signer, store }
    }

    /// Idempotently record a request. Existing ready/failed requests are not
    /// reset by a duplicate login.
    pub fn request(&self, user_id: u64, now: i64) -> Result<EnqueueOutcome, StoreError> {
        self.store.enqueue(user_id, now)
    }

    /// Claim and process at most one request. A crashed worker's expired
    /// lease is claimable by the next invocation; a live lease is not.
    pub fn process_one(
        &self,
        worker_id: &str,
        now: i64,
    ) -> Result<Processed, StoreError> {
        let Some(task) = self.store.claim(worker_id, now, LEASE_SECONDS)? else {
            return Ok(Processed::NoWork);
        };

        // A wallet that appeared after enqueue (including a previous worker
        // committing before a crash) is authoritative. Never mint again.
        if self.store.wallet_exists(task.user_id)? {
            self.store.mark_ready(task.user_id, now, worker_id)?;
            return Ok(Processed::ReadyExistingWallet);
        }

        match self.signer.ensure_wallet(task.user_id) {
            Ok(()) => {
                self.store.mark_ready(task.user_id, now, worker_id)?;
                Ok(Processed::ReadyProvisioned)
            }
            Err(error) if error.class == FailureClass::WalletMissing => {
                // Missing/corrupt registered wallet: explicit operator action
                // is required. Never mint a replacement.
                self.store.mark_failed(
                    task.user_id,
                    now,
                    ProvisionState::WalletMissing,
                    error.code,
                    worker_id,
                )?;
                Ok(Processed::WalletMissing)
            }
            Err(error) if error.class == FailureClass::Permanent => {
                self.store.mark_failed(
                    task.user_id,
                    now,
                    ProvisionState::Failed,
                    error.code,
                    worker_id,
                )?;
                Ok(Processed::Failed)
            }
            Err(error) => {
                if task.attempts >= MAX_ATTEMPTS {
                    self.store.mark_failed(
                        task.user_id,
                        now,
                        ProvisionState::Failed,
                        error.code,
                        worker_id,
                    )?;
                    return Ok(Processed::Failed);
                }
                let next_attempt_at = now.saturating_add(backoff_seconds(task.attempts));
                self.store.reschedule(
                    task.user_id,
                    now,
                    next_attempt_at,
                    error.code,
                    worker_id,
                )?;
                Ok(Processed::RetryScheduled)
            }
        }
    }
}

pub fn backoff_seconds(attempt: u32) -> i64 {
    let exponent = attempt.saturating_sub(1).min(6);
    (BACKOFF_BASE_SECONDS << exponent).min(BACKOFF_MAX_SECONDS)
}

/// Real PostgreSQL adapter for the V8 outbox.
///
/// The adapter is deliberately pure coordination: it stores user ids, states,
/// attempt counters and static error codes. It never stores key material or
/// raw signer/database error text. It owns a dedicated runtime handle; callers
/// must invoke it outside that runtime's asynchronous context (the tests use a
/// normal thread and a dedicated runtime, and the server integration would use
/// a blocking worker).
pub struct PgProvisionStore {
    client: std::sync::Arc<tokio_postgres::Client>,
    runtime: std::sync::Arc<tokio::runtime::Runtime>,
}

impl PgProvisionStore {
    pub fn new(
        client: std::sync::Arc<tokio_postgres::Client>,
        runtime: std::sync::Arc<tokio::runtime::Runtime>,
    ) -> Self {
        Self { client, runtime }
    }

    fn run<T, F>(&self, future: F) -> Result<T, StoreError>
    where
        F: std::future::Future<Output = Result<T, tokio_postgres::Error>>,
    {
        self.runtime.block_on(future).map_err(|_| StoreError)
    }
}

impl ProvisionStore for PgProvisionStore {
    fn enqueue(&self, user_id: u64, now: i64) -> Result<EnqueueOutcome, StoreError> {
        let inserted = self.run(self.client.execute(
            "INSERT INTO wallet_provision_requests
               (user_id, state, attempts, next_attempt_at, requested_at, updated_at)
             VALUES ($1, 'pending', 0, $2, $2, $2)
             ON CONFLICT (user_id) DO NOTHING",
            &[&(user_id as i64), &now],
        ))?;
        Ok(if inserted == 1 {
            EnqueueOutcome::Created
        } else {
            EnqueueOutcome::AlreadyPresent
        })
    }

    fn wallet_exists(&self, user_id: u64) -> Result<bool, StoreError> {
        let row = self.run(self.client.query_opt(
            "SELECT 1 FROM user_wallets WHERE user_id = $1",
            &[&(user_id as i64)],
        ))?;
        Ok(row.is_some())
    }

    fn claim(
        &self,
        worker_id: &str,
        now: i64,
        lease_seconds: i64,
    ) -> Result<Option<ProvisionTask>, StoreError> {
        let row = self.run(self.client.query_opt(
            "WITH candidate AS (
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
             RETURNING r.user_id, r.attempts",
            &[&now, &lease_seconds, &worker_id],
        ))?;
        Ok(row.map(|r| ProvisionTask {
            user_id: r.get::<_, i64>(0) as u64,
            attempts: r.get::<_, i32>(1) as u32,
        }))
    }

    fn mark_ready(&self, user_id: u64, now: i64, worker_id: &str) -> Result<(), StoreError> {
        // The worker_id predicate is the fencing token: a worker whose lease
        // was taken over can update zero rows and must not report success.
        // The registry predicate is the readiness proof: a signer call that
        // returned success but did not publish a public registry row must not
        // be marked ready.
        let changed = self.run(self.client.execute(
            "UPDATE wallet_provision_requests
             SET state = 'ready', lease_until = NULL, worker_id = NULL,
                 last_error_code = NULL, updated_at = $2
             WHERE user_id = $1 AND state = 'provisioning' AND worker_id = $3
               AND EXISTS (SELECT 1 FROM user_wallets WHERE user_id = $1)",
            &[&(user_id as i64), &now, &worker_id],
        ))?;
        if changed == 1 {
            Ok(())
        } else {
            Err(StoreError)
        }
    }

    fn reschedule(
        &self,
        user_id: u64,
        now: i64,
        next_attempt_at: i64,
        error_code: &'static str,
        worker_id: &str,
    ) -> Result<(), StoreError> {
        self.run(self.client.execute(
            "UPDATE wallet_provision_requests
             SET state = 'pending', lease_until = NULL, worker_id = NULL,
                 next_attempt_at = $3, last_error_code = $4, updated_at = $2
             WHERE user_id = $1 AND state = 'provisioning' AND worker_id = $5",
            &[&(user_id as i64), &now, &next_attempt_at, &error_code, &worker_id],
        ))?;
        Ok(())
    }

    fn mark_failed(
        &self,
        user_id: u64,
        now: i64,
        state: ProvisionState,
        error_code: &'static str,
        worker_id: &str,
    ) -> Result<(), StoreError> {
        let terminal = match state {
            ProvisionState::Failed => "failed",
            ProvisionState::WalletMissing => "wallet_missing",
            _ => return Err(StoreError),
        };
        self.run(self.client.execute(
            "UPDATE wallet_provision_requests
             SET state = $3, lease_until = NULL, worker_id = NULL,
                 last_error_code = $4, updated_at = $2
             WHERE user_id = $1 AND state = 'provisioning' AND worker_id = $5",
            &[&(user_id as i64), &now, &terminal, &error_code, &worker_id],
        ))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    #[derive(Clone)]
    struct MemoryStore {
        inner: Arc<Mutex<Inner>>,
    }

    #[derive(Default)]
    struct Inner {
        rows: HashMap<u64, Row>,
        wallets: HashSet<u64>,
    }

    #[derive(Clone, Debug)]
    struct Row {
        state: ProvisionState,
        attempts: u32,
        next_attempt_at: i64,
        lease_until: Option<i64>,
        worker_id: Option<String>,
        last_error_code: Option<&'static str>,
        requested_at: i64,
        updated_at: i64,
    }

    impl MemoryStore {
        fn new() -> Self {
            Self {
                inner: Arc::new(Mutex::new(Inner::default())),
            }
        }

        fn seed_wallet(&self, user_id: u64) {
            self.inner.lock().unwrap().wallets.insert(user_id);
        }

        fn row(&self, user_id: u64) -> Option<Row> {
            self.inner.lock().unwrap().rows.get(&user_id).cloned()
        }

        fn state(&self, user_id: u64) -> Option<ProvisionState> {
            self.row(user_id).map(|row| row.state)
        }
    }

    impl ProvisionStore for MemoryStore {
        fn enqueue(&self, user_id: u64, now: i64) -> Result<EnqueueOutcome, StoreError> {
            let mut inner = self.inner.lock().map_err(|_| StoreError)?;
            if let Some(existing) = inner.rows.get(&user_id) {
                // A duplicate login must not reset a ready, failed, or
                // wallet_missing request. It also must not duplicate pending.
                let _ = existing;
                return Ok(EnqueueOutcome::AlreadyPresent);
            }
            inner.rows.insert(
                user_id,
                Row {
                    state: ProvisionState::Pending,
                    attempts: 0,
                    next_attempt_at: now,
                    lease_until: None,
                    worker_id: None,
                    last_error_code: None,
                    requested_at: now,
                    updated_at: now,
                },
            );
            Ok(EnqueueOutcome::Created)
        }

        fn wallet_exists(&self, user_id: u64) -> Result<bool, StoreError> {
            Ok(self
                .inner
                .lock()
                .map_err(|_| StoreError)?
                .wallets
                .contains(&user_id))
        }

        fn claim(
            &self,
            worker_id: &str,
            now: i64,
            lease_seconds: i64,
        ) -> Result<Option<ProvisionTask>, StoreError> {
            let mut inner = self.inner.lock().map_err(|_| StoreError)?;
            let candidate = inner
                .rows
                .iter()
                .filter(|(_, row)| match row.state {
                    ProvisionState::Pending => row.next_attempt_at <= now,
                    ProvisionState::Provisioning => {
                        row.lease_until.map(|until| until < now).unwrap_or(true)
                    }
                    ProvisionState::Ready
                    | ProvisionState::Failed
                    | ProvisionState::WalletMissing => false,
                })
                .min_by_key(|(user_id, row)| (row.requested_at, *user_id))
                .map(|(user_id, _)| *user_id);

            let Some(user_id) = candidate else {
                return Ok(None);
            };
            let row = inner.rows.get_mut(&user_id).expect("candidate row");
            row.state = ProvisionState::Provisioning;
            row.attempts = row.attempts.saturating_add(1);
            row.lease_until = Some(now.saturating_add(lease_seconds));
            row.worker_id = Some(worker_id.to_string());
            row.updated_at = now;
            Ok(Some(ProvisionTask {
                user_id,
                attempts: row.attempts,
            }))
        }

        fn mark_ready(&self, user_id: u64, now: i64, worker_id: &str) -> Result<(), StoreError> {
            let mut inner = self.inner.lock().map_err(|_| StoreError)?;
            let row = inner.rows.get_mut(&user_id).ok_or(StoreError)?;
            if row.state == ProvisionState::Ready {
                return Ok(());
            }
            if row.state != ProvisionState::Provisioning
                || row.worker_id.as_deref() != Some(worker_id)
            {
                return Ok(());
            }
            row.state = ProvisionState::Ready;
            row.lease_until = None;
            row.worker_id = None;
            row.last_error_code = None;
            row.updated_at = now;
            Ok(())
        }

        fn reschedule(
            &self,
            user_id: u64,
            now: i64,
            next_attempt_at: i64,
            error_code: &'static str,
            worker_id: &str,
        ) -> Result<(), StoreError> {
            let mut inner = self.inner.lock().map_err(|_| StoreError)?;
            let row = inner.rows.get_mut(&user_id).ok_or(StoreError)?;
            if row.state != ProvisionState::Provisioning
                || row.worker_id.as_deref() != Some(worker_id)
            {
                return Ok(());
            }
            row.state = ProvisionState::Pending;
            row.next_attempt_at = next_attempt_at;
            row.lease_until = None;
            row.worker_id = None;
            row.last_error_code = Some(error_code);
            row.updated_at = now;
            Ok(())
        }

        fn mark_failed(
            &self,
            user_id: u64,
            now: i64,
            state: ProvisionState,
            error_code: &'static str,
            worker_id: &str,
        ) -> Result<(), StoreError> {
            debug_assert!(matches!(state, ProvisionState::Failed | ProvisionState::WalletMissing));
            let mut inner = self.inner.lock().map_err(|_| StoreError)?;
            let row = inner.rows.get_mut(&user_id).ok_or(StoreError)?;
            if row.state != ProvisionState::Provisioning
                || row.worker_id.as_deref() != Some(worker_id)
            {
                return Ok(());
            }
            row.state = state;
            row.lease_until = None;
            row.worker_id = None;
            row.last_error_code = Some(error_code);
            row.updated_at = now;
            Ok(())
        }
    }

    struct FakeSigner {
        calls: Arc<AtomicUsize>,
        result: Mutex<Result<(), SignerError>>,
    }

    impl FakeSigner {
        fn success() -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                result: Mutex::new(Ok(())),
            }
        }

        fn failure(error: SignerError) -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                result: Mutex::new(Err(error)),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn replace(&self, result: Result<(), SignerError>) {
            *self.result.lock().unwrap() = result;
        }
    }

    impl ProvisionSigner for FakeSigner {
        fn ensure_wallet(&self, _user_id: u64) -> Result<(), SignerError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.result.lock().unwrap().clone()
        }
    }

    #[test]
    fn restart_after_ready_preserves_terminal_state() {
        let store = MemoryStore::new();
        assert_eq!(store.enqueue(31, 100).unwrap(), EnqueueOutcome::Created);
        let signer = FakeSigner::success();
        let first = Provisioner::new(&signer, &store);
        assert_eq!(first.process_one("worker-a", 101).unwrap(), Processed::ReadyProvisioned);
        assert_eq!(store.state(31), Some(ProvisionState::Ready));

        // Simulate a fresh process/store handle after restart.
        let second = Provisioner::new(FakeSigner::success(), MemoryStore { inner: store.inner.clone() });
        assert_eq!(second.request(31, 102).unwrap(), EnqueueOutcome::AlreadyPresent);
        assert_eq!(second.process_one("worker-b", 103).unwrap(), Processed::NoWork);
        assert_eq!(store.state(31), Some(ProvisionState::Ready));
    }

    #[test]
    fn restart_after_retry_preserves_backoff_not_duplicate_work() {
        let store = MemoryStore::new();
        assert_eq!(store.enqueue(32, 100).unwrap(), EnqueueOutcome::Created);
        let failing = FakeSigner::failure(SignerError::transient("PROVISIONER_BUSY"));
        let first = Provisioner::new(failing, &store);
        assert_eq!(
            first.process_one("worker-a", 101).unwrap(),
            Processed::RetryScheduled
        );
        let row = store.row(32).unwrap();
        assert_eq!(row.state, ProvisionState::Pending);
        let retry_at = row.next_attempt_at;

        let second = Provisioner::new(FakeSigner::success(), MemoryStore { inner: store.inner.clone() });
        assert_eq!(second.process_one("worker-b", retry_at - 1).unwrap(), Processed::NoWork);
        assert_eq!(second.process_one("worker-b", retry_at).unwrap(), Processed::ReadyProvisioned);
    }

    #[test]
    fn enqueue_is_idempotent_and_existing_wallet_is_never_minted() {
        let store = MemoryStore::new();
        store.seed_wallet(42);
        let signer = FakeSigner::success();
        let provisioner = Provisioner::new(&signer, &store);

        assert_eq!(provisioner.request(42, 100), Ok(EnqueueOutcome::Created));
        assert_eq!(provisioner.request(42, 101), Ok(EnqueueOutcome::AlreadyPresent));
        let processed = provisioner.process_one("worker-a", 102).unwrap();
        assert_eq!(processed, Processed::ReadyExistingWallet);
        assert_eq!(signer.calls(), 0);
        assert_eq!(store.state(42), Some(ProvisionState::Ready));
    }

    #[test]
    fn concurrent_workers_claim_one_request_once() {
        let store = MemoryStore::new();
        assert_eq!(store.enqueue(7, 100).unwrap(), EnqueueOutcome::Created);
        let signer = Arc::new(FakeSigner::success());
        let signer_a = Arc::clone(&signer);
        let signer_b = Arc::clone(&signer);
        let store_a = store.inner.clone();
        let store_b = store.inner.clone();

        let t1 = thread::spawn(move || {
            let store = MemoryStore { inner: store_a };
            Provisioner::new(signer_a, store).process_one("worker-a", 101)
        });
        let t2 = thread::spawn(move || {
            let store = MemoryStore { inner: store_b };
            Provisioner::new(signer_b, store).process_one("worker-b", 101)
        });
        let r1 = t1.join().unwrap().unwrap();
        let r2 = t2.join().unwrap().unwrap();

        assert_eq!(
            [r1, r2].iter().filter(|r| **r != Processed::NoWork).count(),
            1,
            "exactly one worker must claim the row"
        );
        assert_eq!(signer.calls(), 1);
        assert_eq!(store.state(7), Some(ProvisionState::Ready));
    }

    #[test]
    fn expired_lease_is_recovered_after_restart() {
        let store = MemoryStore::new();
        store.enqueue(9, 100).unwrap();
        let signer = FakeSigner::success();
        let provisioner = Provisioner::new(&signer, &store);

        let task = store.claim("crashed-worker", 100, 10).unwrap().unwrap();
        assert_eq!(task.user_id, 9);
        // A live lease cannot be stolen.
        assert!(store.claim("second-worker", 105, 10).unwrap().is_none());

        // A new process after lease expiry can recover it.
        let processed = provisioner.process_one("restarted-worker", 111).unwrap();
        assert_eq!(processed, Processed::ReadyProvisioned);
        assert_eq!(signer.calls(), 1);
        assert_eq!(store.state(9), Some(ProvisionState::Ready));
    }

    #[test]
    fn transient_failure_is_retried_with_backoff() {
        let store = MemoryStore::new();
        store.enqueue(11, 100).unwrap();
        let signer = FakeSigner::failure(SignerError::transient("PROVISIONER_BUSY"));
        let provisioner = Provisioner::new(&signer, &store);

        assert_eq!(
            provisioner.process_one("worker-a", 101).unwrap(),
            Processed::RetryScheduled
        );
        let row = store.row(11).unwrap();
        assert_eq!(row.state, ProvisionState::Pending);
        assert_eq!(row.last_error_code, Some("PROVISIONER_BUSY"));
        assert!(row.next_attempt_at > 101);
        assert_eq!(row.attempts, 1);

        // Before the backoff deadline, no claim; after it, the retry runs.
        assert!(store.claim("worker-b", 102, LEASE_SECONDS).unwrap().is_none());
        signer.replace(Ok(()));
        assert_eq!(
            provisioner.process_one("worker-b", 106).unwrap(),
            Processed::ReadyProvisioned
        );
        assert_eq!(store.state(11), Some(ProvisionState::Ready));
    }

    #[test]
    fn wallet_missing_is_terminal_and_never_mints_a_replacement() {
        let store = MemoryStore::new();
        store.enqueue(13, 100).unwrap();
        let signer = FakeSigner::failure(SignerError::wallet_missing("WALLET_FILE_MISSING"));
        let provisioner = Provisioner::new(&signer, &store);

        assert_eq!(
            provisioner.process_one("worker-a", 101).unwrap(),
            Processed::WalletMissing
        );
        assert_eq!(store.state(13), Some(ProvisionState::WalletMissing));
        assert_eq!(signer.calls(), 1);

        // Re-enqueue is idempotent and does not reset the terminal state.
        assert_eq!(provisioner.request(13, 102), Ok(EnqueueOutcome::AlreadyPresent));
        assert!(store.claim("worker-b", 102, LEASE_SECONDS).unwrap().is_none());
        assert_eq!(signer.calls(), 1);
    }

    #[test]
    fn stale_worker_cannot_commit_after_lease_takeover() {
        let store = MemoryStore::new();
        store.enqueue(21, 100).unwrap();
        let old = store.claim("old-worker", 100, 10).unwrap().unwrap();
        assert_eq!(old.user_id, 21);

        let new = store.claim("new-worker", 111, 10).unwrap().unwrap();
        assert_eq!(new.user_id, 21);

        // The old worker must not be able to mark the row ready after its
        // lease was taken over.
        store.mark_ready(21, 112, "old-worker").unwrap();
        assert_eq!(store.state(21), Some(ProvisionState::Provisioning));

        store.mark_ready(21, 112, "new-worker").unwrap();
        assert_eq!(store.state(21), Some(ProvisionState::Ready));
    }

    #[test]
    fn attempts_are_bounded_and_never_loop_forever() {
        let store = MemoryStore::new();
        store.enqueue(15, 100).unwrap();
        let signer = FakeSigner::failure(SignerError::transient("PROVISIONER_BUSY"));
        let provisioner = Provisioner::new(&signer, &store);
        let mut now = 101;
        for _ in 0..MAX_ATTEMPTS {
            let _ = provisioner.process_one("worker", now).unwrap();
            now = store.row(15).map(|r| r.next_attempt_at).unwrap_or(now) + 1;
        }
        assert_eq!(store.state(15), Some(ProvisionState::Failed));
        assert_eq!(signer.calls(), MAX_ATTEMPTS as usize);
    }

    #[test]
    fn outbox_rows_and_errors_contain_no_key_or_secret_material() {
        let store = MemoryStore::new();
        store.enqueue(17, 100).unwrap();
        let signer = FakeSigner::failure(SignerError::wallet_missing("WALLET_FILE_MISSING"));
        let provisioner = Provisioner::new(&signer, &store);
        let _ = provisioner.process_one("worker", 101).unwrap();
        let row = store.row(17).unwrap();
        let debug = format!("{row:?}");
        for forbidden in [
            "private",
            "seed",
            "secret",
            "BEGIN",
            "keypair",
            "signature",
        ] {
            assert!(
                !debug.to_ascii_lowercase().contains(forbidden),
                "outbox row must not contain {forbidden:?}"
            );
        }
        assert_eq!(row.last_error_code, Some("WALLET_FILE_MISSING"));
    }
}
