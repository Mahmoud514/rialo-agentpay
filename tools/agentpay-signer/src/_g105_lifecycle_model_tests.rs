//! G105 — EXECUTABLE SPECIFICATION ONLY (TEST-ONLY).
//!
//! A pure, in-memory model of the approved lifecycle decisions (D1–D13) used
//! to pin transition semantics before implementation: one active key per user,
//! generation bump on rotation, replay rejection, terminal revocation, and
//! cross-user isolation. It performs NO I/O, NO crypto, NO persistence, and is
//! NOT wired into the signer or any production path.

use std::collections::{BTreeMap, HashSet};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Status {
    Bound,
    Active,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Binding {
    pubkey: String,
    generation: u64,
    status: Status,
}

#[derive(Debug, PartialEq, Eq)]
enum Deny {
    BadInput,
    Duplicate,
    Unbound,
    Revoked,
    StaleGeneration,
    Replay,
}

#[derive(Default)]
struct Model {
    bindings: BTreeMap<u64, Binding>,
    nonces: HashSet<String>,
}

impl Model {
    fn consume(&mut self, nonce: &str) -> Result<(), Deny> {
        if nonce.is_empty() {
            return Err(Deny::BadInput);
        }
        if !self.nonces.insert(nonce.to_string()) {
            return Err(Deny::Replay);
        }
        Ok(())
    }

    fn enroll(&mut self, user: u64, pubkey: &str, nonce: &str) -> Result<(), Deny> {
        if pubkey.is_empty() {
            return Err(Deny::BadInput);
        }
        if self.bindings.contains_key(&user) {
            return Err(Deny::Duplicate);
        }
        self.consume(nonce)?;
        self.bindings.insert(
            user,
            Binding {
                pubkey: pubkey.to_string(),
                generation: 1,
                status: Status::Bound,
            },
        );
        Ok(())
    }

    fn activate(&mut self, user: u64) -> Result<(), Deny> {
        let b = self.bindings.get_mut(&user).ok_or(Deny::Unbound)?;
        if b.status != Status::Bound {
            return Err(Deny::StaleGeneration);
        }
        b.status = Status::Active;
        Ok(())
    }

    fn rotate(
        &mut self,
        user: u64,
        expected_generation: u64,
        new_pubkey: &str,
        nonce: &str,
    ) -> Result<(), Deny> {
        if new_pubkey.is_empty() {
            return Err(Deny::BadInput);
        }
        let b = self.bindings.get(&user).ok_or(Deny::Unbound)?;
        if b.status == Status::Revoked {
            return Err(Deny::Revoked);
        }
        if b.status != Status::Active {
            return Err(Deny::StaleGeneration);
        }
        if b.generation != expected_generation {
            return Err(Deny::StaleGeneration);
        }
        if b.pubkey == new_pubkey {
            return Err(Deny::BadInput);
        }
        self.consume(nonce)?;
        let b = self.bindings.get_mut(&user).unwrap();
        b.pubkey = new_pubkey.to_string();
        b.generation += 1;
        Ok(())
    }

    fn revoke(&mut self, user: u64, nonce: &str) -> Result<(), Deny> {
        let b = self.bindings.get(&user).ok_or(Deny::Unbound)?;
        if b.status == Status::Revoked {
            return Err(Deny::Revoked);
        }
        self.consume(nonce)?;
        self.bindings.get_mut(&user).unwrap().status = Status::Revoked;
        Ok(())
    }

    fn sign_allowed(&self, user: u64) -> bool {
        self.bindings
            .get(&user)
            .map(|b| b.status == Status::Active)
            .unwrap_or(false)
    }
}

#[test]
fn g105_model_enroll_is_single_and_cross_user_isolated() {
    let mut m = Model::default();
    assert!(m.enroll(1, "A", "n1").is_ok());
    assert_eq!(m.enroll(1, "B", "n2"), Err(Deny::Duplicate));
    assert!(m.enroll(2, "C", "n3").is_ok(), "user 2 unaffected");
    assert_eq!(m.bindings[&1].pubkey, "A");
    assert_eq!(m.bindings[&2].pubkey, "C");
}

#[test]
fn g105_model_activation_and_rotation_bump_generation() {
    let mut m = Model::default();
    m.enroll(1, "A", "n1").unwrap();
    assert!(!m.sign_allowed(1), "bound but not active");
    m.activate(1).unwrap();
    assert!(m.sign_allowed(1));
    m.rotate(1, 1, "B", "n2").unwrap();
    assert_eq!(m.bindings[&1].generation, 2);
    assert_eq!(m.bindings[&1].pubkey, "B");
    assert_eq!(m.rotate(1, 1, "C", "n3"), Err(Deny::StaleGeneration));
    assert_eq!(m.rotate(1, 2, "B", "n4"), Err(Deny::BadInput), "same key");
}

#[test]
fn g105_model_replay_and_cross_user_rotation_are_rejected() {
    let mut m = Model::default();
    m.enroll(1, "A", "n1").unwrap();
    m.enroll(2, "B", "n2").unwrap();
    m.activate(1).unwrap();
    m.activate(2).unwrap();
    assert_eq!(m.rotate(1, 1, "C", "n1"), Err(Deny::Replay), "reused nonce");
    assert_eq!(
        m.rotate(2, 1, "C", "n1"),
        Err(Deny::Replay),
        "global replay"
    );
    // user 1's generation does not authorize user 2
    assert_eq!(m.rotate(2, 2, "D", "n5"), Err(Deny::StaleGeneration));
}

#[test]
fn g105_model_revocation_is_terminal_and_blocks_signing() {
    let mut m = Model::default();
    m.enroll(1, "A", "n1").unwrap();
    m.activate(1).unwrap();
    m.revoke(1, "n2").unwrap();
    assert!(!m.sign_allowed(1));
    assert_eq!(m.rotate(1, 1, "B", "n3"), Err(Deny::Revoked));
    assert_eq!(m.revoke(1, "n4"), Err(Deny::Revoked), "idempotent refusal");
    assert_eq!(
        m.enroll(1, "B", "n5"),
        Err(Deny::Duplicate),
        "re-enroll needs operator path"
    );
    // another user is unaffected
    m.enroll(2, "Z", "n6").unwrap();
    m.activate(2).unwrap();
    assert!(m.sign_allowed(2));
}

#[test]
fn g105_model_malformed_inputs_are_rejected() {
    let mut m = Model::default();
    assert_eq!(m.enroll(1, "", "n1"), Err(Deny::BadInput));
    assert_eq!(m.enroll(1, "A", ""), Err(Deny::BadInput));
    assert_eq!(m.rotate(9, 1, "B", "n2"), Err(Deny::Unbound));
    assert_eq!(m.revoke(9, "n3"), Err(Deny::Unbound));
    assert!(!m.sign_allowed(9));
}

// --- G107: transition edge cases -------------------------------------------

#[test]
fn g107_double_activation_and_revoke_before_activation_are_rejected() {
    let mut m = Model::default();
    m.enroll(7, "pk7", "a1").unwrap();
    m.activate(7).unwrap();
    assert_eq!(m.activate(7), Err(Deny::StaleGeneration), "double activate");

    m.enroll(8, "pk8", "a2").unwrap();
    m.revoke(8, "a3").unwrap();
    assert!(!m.sign_allowed(8));
    assert_eq!(
        m.activate(8),
        Err(Deny::StaleGeneration),
        "activate revoked"
    );
    assert_eq!(m.rotate(8, 1, "pk8b", "a4"), Err(Deny::Revoked));
}

#[test]
fn g107_nonce_is_global_and_cannot_be_reused_across_users() {
    let mut m = Model::default();
    m.enroll(1, "pk1", "shared").unwrap();
    assert_eq!(m.enroll(2, "pk2", "shared"), Err(Deny::Replay));
    assert!(!m.sign_allowed(2));
}
