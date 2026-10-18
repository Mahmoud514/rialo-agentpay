//! Tests for Tasks Marketplace module

#[path = "server/_tasks_tests.rs"]
#[cfg(test)]
mod tasks_tests;
    use uuid::Uuid;

    /// PHASE 9 — sync cwd isolation sharing the ONE crate-wide CWD lock
    /// (std::sync::Mutex since the unification in stats.rs). Fixture writes
    /// through the production task_path()/reservation_path() land in the
    /// per-call temp sandbox, never the real artifact/ tree.
    fn isolated_cwd<R: std::panic::UnwindSafe>(
        f: impl FnOnce() -> R + std::panic::UnwindSafe,
    ) -> R {
        let _g = crate::stats::tests24::tests24::CWD_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let original = std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir());
        let sandbox =
            std::env::temp_dir().join(format!("agentpay-taskstests-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&sandbox).expect("create isolation sandbox");
        std::env::set_current_dir(&sandbox).expect("enter isolation sandbox");
        let result = std::panic::catch_unwind(f);
        let _ = std::env::set_current_dir(&original);
        let _ = std::fs::remove_dir_all(&sandbox);
        match result {
            Ok(v) => v,
            Err(p) => std::panic::resume_unwind(p),
        }
    }

    fn setup_test_env() {
        // Clean up any existing test data
        let _ = fs::remove_dir_all("artifact/test_tasks");
        let _ = fs::remove_dir_all("artifact/test_reservations");
    }

    fn teardown_test_env() {
        let _ = fs::remove_dir_all("artifact/test_tasks");
        let _ = fs::remove_dir_all("artifact/test_reservations");
    }

    #[test]
    fn test_task_status_transitions() {
        // Valid transitions
        assert!(TaskStatus::Open.can_transition(TaskStatus::InProgress));
        assert!(TaskStatus::Open.can_transition(TaskStatus::Cancelled));
        assert!(TaskStatus::InProgress.can_transition(TaskStatus::Submitted));
        assert!(TaskStatus::Submitted.can_transition(TaskStatus::UnderReview));
        assert!(TaskStatus::UnderReview.can_transition(TaskStatus::Approved));
        assert!(TaskStatus::UnderReview.can_transition(TaskStatus::Rejected));
        assert!(TaskStatus::UnderReview.can_transition(TaskStatus::RevisionRequested));
        assert!(TaskStatus::RevisionRequested.can_transition(TaskStatus::Submitted));
        assert!(TaskStatus::Approved.can_transition(TaskStatus::Paid));
        assert!(TaskStatus::Approved.can_transition(TaskStatus::PaymentFailed));

        // Invalid transitions
        assert!(!TaskStatus::Open.can_transition(TaskStatus::Submitted));
        assert!(!TaskStatus::Open.can_transition(TaskStatus::Approved));
        assert!(!TaskStatus::Paid.can_transition(TaskStatus::Open));
        assert!(!TaskStatus::Cancelled.can_transition(TaskStatus::Open));
        assert!(!TaskStatus::Rejected.can_transition(TaskStatus::Approved));
    }

    #[test]
    fn test_terminal_states() {
        assert!(TaskStatus::Paid.is_terminal());
        assert!(TaskStatus::Rejected.is_terminal());
        assert!(TaskStatus::Cancelled.is_terminal());
        assert!(TaskStatus::PaymentFailed.is_terminal());

        assert!(!TaskStatus::Open.is_terminal());
        assert!(!TaskStatus::InProgress.is_terminal());
        assert!(!TaskStatus::Submitted.is_terminal());
        assert!(!TaskStatus::UnderReview.is_terminal());
        assert!(!TaskStatus::RevisionRequested.is_terminal());
        assert!(!TaskStatus::Approved.is_terminal());
    }

    #[test]
    fn test_rlo_kelvin_conversions() {
        assert_eq!(rlo_to_kelvin(1.0), 1_000_000_000);
        assert_eq!(rlo_to_kelvin(0.5), 500_000_000);
        assert_eq!(rlo_to_kelvin(10.5), 10_500_000_000);

        assert_eq!(kelvin_to_rlo(1_000_000_000), 1.0);
        assert_eq!(kelvin_to_rlo(500_000_000), 0.5);
    }

    #[test]
    fn test_task_and_reservation_persistence() {
        isolated_cwd(|| {
            setup_test_env();

            let task_id = Uuid::new_v4().to_string();
            let now = now_unix();

            let task = Task {
                schema_version: TASK_SCHEMA_VERSION,
                task_id: task_id.clone(),
                agent_id: Uuid::new_v4().to_string(),
                owner_user_id: 12345,
                owner_name: "test_user".to_string(),
                title: "Test Task".to_string(),
                description: "Test Description".to_string(),
                acceptance_criteria: "Test Criteria".to_string(),
                status: TaskStatus::Open,
                worker_id: None,
                worker_name: None,
                worker_recipient: None,
                reward_kelvin: 1_000_000_000,
                reward_rlo: 1.0,
                submission_url: None,
                submission_notes: None,
                submission_files: Vec::new(),
                review_notes: None,
                revision_count: 0,
                payment_intent_id: None,
                payment_tx_signature: None,
                payment_error: None,
                created_at: now,
                updated_at: now,
            };

            let reservation = TaskReservation {
                schema_version: RESERVATION_SCHEMA_VERSION,
                task_id: task_id.clone(),
                agent_id: task.agent_id.clone(),
                owner_user_id: 12345,
                amount_kelvin: 1_000_000_000,
                status: ReservationStatus::Active,
                created_at: now,
                released_at: None,
                released_reason: None,
                consumed_at: None,
            };

            // Write
            write_json_atomic(&task_path(&task_id), &task).unwrap();
            write_json_atomic(&reservation_path(&task_id), &reservation).unwrap();

            // Read back
            let read_task = read_task(&task_id).unwrap();
            let read_reservation = read_reservation(&task_id).unwrap();

            assert_eq!(read_task.task_id, task_id);
            assert_eq!(read_task.title, "Test Task");
            assert_eq!(read_reservation.amount_kelvin, 1_000_000_000);
            assert!(matches!(read_reservation.status, ReservationStatus::Active));

            // Cleanup
            let _ = fs::remove_file(task_path(&task_id));
            let _ = fs::remove_file(reservation_path(&task_id));
            teardown_test_env();
    
        });
}

    #[test]
    fn test_reservation_release_and_consume() {
        isolated_cwd(|| {
            setup_test_env();

            let task_id = Uuid::new_v4().to_string();
            let now = now_unix();

            let reservation = TaskReservation {
                schema_version: RESERVATION_SCHEMA_VERSION,
                task_id: task_id.clone(),
                agent_id: Uuid::new_v4().to_string(),
                owner_user_id: 12345,
                amount_kelvin: 1_000_000_000,
                status: ReservationStatus::Active,
                created_at: now,
                released_at: None,
                released_reason: None,
                consumed_at: None,
            };

            write_json_atomic(&reservation_path(&task_id), &reservation).unwrap();

            // Test release
            let released = release_reservation(&task_id, "test_release").unwrap();
            assert!(matches!(released.status, ReservationStatus::Released));
            assert!(released.released_at.is_some());
            assert_eq!(released.released_reason, Some("test_release".to_string()));

            // Cannot release again
            let result = release_reservation(&task_id, "second_attempt");
            assert!(result.is_err());

            // Cleanup
            teardown_test_env();
    
        });
}

    #[test]
    fn test_duplicate_reservation_prevention() {
        isolated_cwd(|| {
            // This test verifies that two tasks cannot reserve the same balance
            // In practice, this is enforced by:
            // 1. Atomic balance check at creation time
            // 2. Mutex lock during reservation creation
            // 3. Sum of all active reservations compared against available balance

            // The actual concurrent test would require async runtime
            // For now, we verify the calculation logic

            let agent_id = "test_agent_123";

            // Clean up
            let _ = fs::remove_dir_all(task_reservations_dir());

            // No reservations initially
            assert_eq!(calculate_reserved_amount(agent_id).unwrap(), 0);

            // Simulate adding reservations
            let task1_id = Uuid::new_v4().to_string();
            let task2_id = Uuid::new_v4().to_string();
            let now = now_unix();

            let res1 = TaskReservation {
                schema_version: RESERVATION_SCHEMA_VERSION,
                task_id: task1_id,
                agent_id: agent_id.to_string(),
                owner_user_id: 1,
                amount_kelvin: 500_000_000,
                status: ReservationStatus::Active,
                created_at: now,
                released_at: None,
                released_reason: None,
                consumed_at: None,
            };

            let res2 = TaskReservation {
                schema_version: RESERVATION_SCHEMA_VERSION,
                task_id: task2_id,
                agent_id: agent_id.to_string(),
                owner_user_id: 1,
                amount_kelvin: 300_000_000,
                status: ReservationStatus::Active,
                created_at: now,
                released_at: None,
                released_reason: None,
                consumed_at: None,
            };

            ensure_dirs().unwrap();
            write_json_atomic(&reservation_path(&res1.task_id), &res1).unwrap();
            write_json_atomic(&reservation_path(&res2.task_id), &res2).unwrap();

            // Check total reserved
            assert_eq!(calculate_reserved_amount(agent_id).unwrap(), 800_000_000);

            // Release one
            release_reservation(&res1.task_id, "test").unwrap();
            assert_eq!(calculate_reserved_amount(agent_id).unwrap(), 300_000_000);

            // Cleanup
            let _ = fs::remove_dir_all(task_reservations_dir());
    
        });
}
}
