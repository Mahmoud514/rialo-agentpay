// Test-only PostgreSQL adapter for the Worker auth router.
// This is not the production Neon adapter; it exercises the same SQL semantics
// against the disposable embedded PostgreSQL instance.
import pg from "pg";

export function createPgStore(connectionString) {
  const pool = new pg.Pool({ connectionString, max: 4 });
  const q = (text, params = []) => pool.query(text, params);

  return {
    async close() {
      await pool.end();
    },

    async createNonce(row) {
      await q(
        `INSERT INTO wallet_nonces
           (nonce_hash, address, purpose, user_id, message, domain, chain_id,
            issued_at, expires_at, consumed_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NULL)`,
        [
          row.nonce_hash,
          row.address,
          row.purpose,
          row.user_id,
          row.message,
          row.domain,
          row.chain_id,
          row.issued_at,
          row.expires_at,
        ],
      );
    },

    async consumeNonce(nonceHash, now) {
      const result = await q(
        `UPDATE wallet_nonces
         SET consumed_at = $2
         WHERE nonce_hash = $1
           AND consumed_at IS NULL
           AND expires_at > $2
         RETURNING nonce_hash, address, purpose, user_id, message, domain,
                   chain_id, issued_at, expires_at, consumed_at`,
        [nonceHash, now],
      );
      return result.rows[0] ?? null;
    },

    async findIdentity(provider, subject) {
      const result = await q(
        `SELECT provider, subject, user_id, login, verified_at
         FROM auth_identities
         WHERE provider = $1 AND subject = $2
         LIMIT 1`,
        [provider, subject],
      );
      return result.rows[0] ?? null;
    },

    async getUserWallet(userId) {
      const result = await q(
        `SELECT pubkey FROM user_wallets WHERE user_id = $1::bigint LIMIT 1`,
        [userId],
      );
      return result.rows[0] ?? null;
    },

    async insertIdentity(row) {
      const result = await q(
        `INSERT INTO auth_identities
           (provider, subject, user_id, login, verified_at)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (provider, subject) DO NOTHING
         RETURNING provider, subject, user_id, login, verified_at`,
        [row.provider, row.subject, row.user_id, row.login, row.verified_at],
      );
      return result.rows[0] ?? null;
    },

    async hasUserActivity(userId) {
      const result = await q(
        `SELECT (
          EXISTS (SELECT 1 FROM tasks_pg WHERE owner_user_id = $1::bigint) OR
          EXISTS (SELECT 1 FROM agents WHERE owner_user_id = $1::bigint) OR
          EXISTS (SELECT 1 FROM user_wallets WHERE user_id = $1::bigint) OR
          EXISTS (SELECT 1 FROM sessions WHERE user_id = $1::bigint)
        ) AS active`,
        [userId],
      );
      return Boolean(result.rows[0]?.active);
    },

    async getProvisioning(userId) {
    try {
      const result = await q(
        `SELECT state, updated_at
         FROM wallet_provision_requests
         WHERE user_id = $1::bigint
         LIMIT 1`,
        [userId],
      );
      const row = result.rows[0];
      return row ? { state: row.state, updated_at: row.updated_at } : null;
    } catch {
      return null;
    }
  },

  async listAgents(userId) {
    const result = await q(
      `SELECT agent_id::text AS agent_id, schema_version, owner_user_id,
              name, status, wallet_address, auth_public_key,
              created_at, updated_at
       FROM agents
       WHERE owner_user_id = $1::bigint AND status <> 'deleted'
       ORDER BY created_at ASC, agent_id ASC`,
      [userId],
    );
    return result.rows;
  },

  async getAgent(userId, agentId) {
    const result = await q(
      `SELECT agent_id::text AS agent_id, schema_version, owner_user_id,
              name, status, wallet_address, auth_public_key,
              created_at, updated_at
       FROM agents
       WHERE agent_id = $1::text AND owner_user_id = $2::bigint
       LIMIT 1`,
      [agentId, userId],
    );
    return result.rows[0] ?? null;
  },

  async listTasks(viewerId) {
    const result = await q(
      `SELECT task_id, title, status, reward_rlo::float8 AS reward_rlo,
              COALESCE(owner_name, '') AS owner_name,
              COALESCE(worker_name, '') AS worker_name,
              created_at::bigint AS created_at
       FROM tasks_pg
       WHERE status NOT IN ('cancelled','paid','rejected','paymentfailed')
         AND (status = 'open' OR
              ($1::bigint IS NOT NULL AND
               (owner_user_id = $1::bigint OR worker_id = $1::bigint)))
       ORDER BY created_at DESC`,
      [viewerId],
    );
    return result.rows;
  },

  async getLeaderboard(userId) {
    const result = await q(
      `SELECT a.agent_id::text AS agent_id, a.name, a.status,
              COUNT(i.*)::bigint AS total_intent_count,
              COUNT(i.*) FILTER (WHERE i.state IN ('confirmed','reconciled_paid'))::bigint AS confirmed_payment_count,
              COALESCE(SUM(i.amount_kelvin) FILTER (WHERE i.state IN ('confirmed','reconciled_paid')), 0)::bigint AS confirmed_payment_volume_kelvin,
              MAX(i.updated_at) FILTER (WHERE i.state IN ('confirmed','reconciled_paid')) AS last_confirmed_at,
              COUNT(i.*) FILTER (WHERE i.state = 'pending')::bigint AS pending_count,
              COUNT(i.*) FILTER (WHERE i.state = 'failed')::bigint AS failed_count,
              COUNT(i.*) FILTER (WHERE i.state = 'unknown')::bigint AS unknown_count,
              COUNT(i.*) FILTER (WHERE i.state IN ('reconciled_paid','reconciled_absent'))::bigint AS reconciled_count
       FROM agents a
       LEFT JOIN payment_intents i ON i.agent_id::text = a.agent_id::text
       WHERE a.owner_user_id = $1::bigint AND a.status <> 'deleted'
       GROUP BY a.agent_id, a.name, a.status
       ORDER BY confirmed_payment_volume_kelvin DESC,
                last_confirmed_at DESC NULLS LAST,
                confirmed_payment_count DESC,
                a.agent_id ASC`,
      [userId],
    );
    return result.rows;
  },

  async getTask(taskId) {
    const result = await q(
      `SELECT to_jsonb(t) AS task FROM tasks_pg t WHERE t.task_id = $1 LIMIT 1`,
      [taskId],
    );
    return result.rows[0]?.task ?? null;
  },

  async listOpenTasks(viewerId) {
    const result = await q(
      `SELECT task_id, title, status, reward_rlo::float8 AS reward_rlo,
              COALESCE(owner_name, '') AS owner_name,
              COALESCE(worker_name, '') AS worker_name,
              created_at::bigint AS created_at
       FROM tasks_pg
       WHERE status NOT IN ('cancelled','paid','rejected','paymentfailed')
         AND (status = 'open' OR
              ($1::bigint IS NOT NULL AND
               (owner_user_id = $1::bigint OR worker_id = $1::bigint)))
       ORDER BY created_at DESC`,
      [viewerId],
    );
    return result.rows;
  },

  async createSession(row) {
      await q(
        `INSERT INTO sessions
           (session_id, session_hash, user_id, login, created_at, expires_at,
            auth_method, csrf_hash)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [
          row.session_id,
          row.session_hash,
          row.user_id,
          row.login,
          row.created_at,
          row.expires_at,
          row.auth_method,
          row.csrf_hash,
        ],
      );
    },

    async getSession({ tokenHash, rawToken, now }) {
      const result = await q(
        `SELECT session_id, session_hash, user_id, login, expires_at,
                auth_method, csrf_hash
         FROM sessions
         WHERE (
           session_hash = $1 OR
           (session_hash IS NULL AND session_id = $2)
         )
           AND (expires_at IS NULL OR expires_at > $3)
         ORDER BY (session_hash = $1) DESC
         LIMIT 1`,
        [tokenHash, rawToken, now],
      );
      return result.rows[0] ?? null;
    },

    async deleteSession(sessionId) {
      await q(`DELETE FROM sessions WHERE session_id = $1`, [sessionId]);
    },

    async setSessionCsrf(sessionId, csrfHash) {
      await q(`UPDATE sessions SET csrf_hash = $1 WHERE session_id = $2`, [
        csrfHash,
        sessionId,
      ]);
    },

    async hitRateLimit(key, windowStart, limit) {
      const result = await q(
        `INSERT INTO auth_rate_limits (rate_key, window_start, count)
         VALUES ($1,$2,1)
         ON CONFLICT (rate_key) DO UPDATE SET
           count = CASE
             WHEN auth_rate_limits.window_start = EXCLUDED.window_start
               THEN auth_rate_limits.count + 1
             ELSE 1
           END,
           window_start = EXCLUDED.window_start
         RETURNING count, window_start`,
        [key, windowStart],
      );
      const count = Number(result.rows[0]?.count ?? 0);
      return { count, limited: count > limit };
    },
  };
}
