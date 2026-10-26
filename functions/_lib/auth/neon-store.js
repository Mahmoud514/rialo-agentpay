// Neon-backed AuthStore for the Worker auth lane.
//
// The connection string is supplied by the Pages environment and is never
// returned to a caller or included in an error response.

import { neon } from "@neondatabase/serverless";

export function createNeonStore(env = {}) {
  const connectionString = env.DATABASE_URL;
  if (!connectionString) {
    throw new Error("DATABASE_URL is not configured");
  }
  const sql = neon(connectionString);

  return {
    async createNonce(row) {
      await sql`
        INSERT INTO wallet_nonces
          (nonce_hash, address, purpose, user_id, message, domain, chain_id,
           issued_at, expires_at, consumed_at)
        VALUES
          (${row.nonce_hash}, ${row.address}, ${row.purpose}, ${row.user_id},
           ${row.message}, ${row.domain}, ${row.chain_id}, ${row.issued_at},
           ${row.expires_at}, NULL)
      `;
    },

    async consumeNonce(nonceHash, now) {
      const rows = await sql`
        UPDATE wallet_nonces
        SET consumed_at = ${now}
        WHERE nonce_hash = ${nonceHash}
          AND consumed_at IS NULL
          AND expires_at > ${now}
        RETURNING nonce_hash, address, purpose, user_id, message, domain,
                  chain_id, issued_at, expires_at, consumed_at
      `;
      return rows[0] ?? null;
    },

    async findIdentity(provider, subject) {
      const rows = await sql`
        SELECT provider, subject, user_id, login, verified_at
        FROM auth_identities
        WHERE provider = ${provider} AND subject = ${subject}
        LIMIT 1
      `;
      return rows[0] ?? null;
    },

    async getUserWallet(userId) {
      const rows = await sql`
        SELECT pubkey FROM user_wallets
        WHERE user_id = ${userId}::bigint
        LIMIT 1
      `;
      return rows[0] ?? null;
    },

    async listAgents(userId) {
      const rows = await sql`
        SELECT agent_id::text AS agent_id, schema_version, owner_user_id,
               name, status, wallet_address, auth_public_key,
               created_at, updated_at
        FROM agents
        WHERE owner_user_id = ${userId}::bigint
          AND status <> 'deleted'
        ORDER BY created_at ASC, agent_id ASC
      `;
      return rows;
    },

    async getAgent(userId, agentId) {
      const rows = await sql`
        SELECT agent_id::text AS agent_id, schema_version, owner_user_id,
               name, status, wallet_address, auth_public_key,
               created_at, updated_at
        FROM agents
        WHERE agent_id = ${agentId}
          AND owner_user_id = ${userId}::bigint
        LIMIT 1
      `;
      return rows[0] ?? null;
    },

    async listTasks(viewerId) {
      const rows = await sql`
        SELECT task_id, title, status, reward_rlo::float8 AS reward_rlo,
               COALESCE(owner_name, '') AS owner_name,
               COALESCE(worker_name, '') AS worker_name,
               created_at::bigint AS created_at
        FROM tasks_pg
        WHERE status NOT IN ('cancelled','paid','rejected','paymentfailed')
          AND (status = 'open' OR
               (${viewerId}::bigint IS NOT NULL AND
                (owner_user_id = ${viewerId}::bigint OR worker_id = ${viewerId}::bigint)))
        ORDER BY created_at DESC
      `;
      return rows;
    },

    async getLeaderboard(userId) {
      const rows = await sql`
        SELECT a.agent_id::text AS agent_id,
               a.name,
               a.status,
               COUNT(i.*)::bigint AS total_intent_count,
               COUNT(i.*) FILTER (
                 WHERE i.state IN ('confirmed', 'reconciled_paid')
               )::bigint AS confirmed_payment_count,
               COALESCE(SUM(i.amount_kelvin) FILTER (
                 WHERE i.state IN ('confirmed', 'reconciled_paid')
               ), 0)::bigint AS confirmed_payment_volume_kelvin,
               MAX(i.updated_at) FILTER (
                 WHERE i.state IN ('confirmed', 'reconciled_paid')
               ) AS last_confirmed_at,
               COUNT(i.*) FILTER (WHERE i.state = 'pending')::bigint AS pending_count,
               COUNT(i.*) FILTER (WHERE i.state = 'failed')::bigint AS failed_count,
               COUNT(i.*) FILTER (WHERE i.state = 'unknown')::bigint AS unknown_count,
               COUNT(i.*) FILTER (
                 WHERE i.state IN ('reconciled_paid', 'reconciled_absent')
               )::bigint AS reconciled_count
        FROM agents a
        LEFT JOIN payment_intents i
          ON i.agent_id::text = a.agent_id::text
        WHERE a.owner_user_id = ${userId}::bigint
          AND a.status <> 'deleted'
        GROUP BY a.agent_id, a.name, a.status
        ORDER BY confirmed_payment_volume_kelvin DESC,
                 last_confirmed_at DESC NULLS LAST,
                 confirmed_payment_count DESC,
                 a.agent_id ASC
      `;
      return rows;
    },

    async getTask(taskId) {
      const rows = await sql`
        SELECT to_jsonb(t) AS task
        FROM tasks_pg t
        WHERE t.task_id = ${taskId}
        LIMIT 1
      `;
      return rows[0]?.task ?? null;
    },

    async getProvisioning(userId) {
      // V8 may not be applied in an older environment. This read-only status
      // lookup must not break login or /api/me when the table is absent.
      try {
        const rows = await sql`
          SELECT state, updated_at
          FROM wallet_provision_requests
          WHERE user_id = ${userId}::bigint
          LIMIT 1
        `;
        const row = rows[0];
        return row ? { state: row.state, updated_at: row.updated_at } : null;
      } catch {
        return null;
      }
    },

    async enqueueProvisioning(userId, now) {
      // Best-effort, idempotent outbox insert. This is intentionally separate
      // from session creation and never waits for a signer/wallet.
      try {
        await sql`
          INSERT INTO wallet_provision_requests
            (user_id, state, attempts, next_attempt_at, requested_at, updated_at)
          VALUES (${userId}::bigint, 'pending', 0, ${now}, ${now}, ${now})
          ON CONFLICT (user_id) DO NOTHING
        `;
        return true;
      } catch {
        return false;
      }
    },

    async listOpenTasks(viewerId) {
      // Public board plus the viewer's own non-terminal tasks. This mirrors
      // the anonymous/owner visibility rule of the existing task listing.
      const rows = await sql`
        SELECT task_id, title, status, reward_rlo::float8 AS reward_rlo,
               COALESCE(owner_name, '') AS owner_name,
               COALESCE(worker_name, '') AS worker_name,
               created_at::bigint AS created_at
        FROM tasks_pg
        WHERE status NOT IN ('cancelled','paid','rejected','paymentfailed')
          AND (status = 'open' OR
               (${viewerId}::bigint IS NOT NULL AND
                (owner_user_id = ${viewerId}::bigint OR worker_id = ${viewerId}::bigint)))
        ORDER BY created_at DESC
      `;
      return rows;
    },

    async insertIdentity(row) {
      const rows = await sql`
        INSERT INTO auth_identities
          (provider, subject, user_id, login, verified_at)
        VALUES
          (${row.provider}, ${row.subject}, ${row.user_id}, ${row.login},
           ${row.verified_at})
        ON CONFLICT (provider, subject) DO NOTHING
        RETURNING provider, subject, user_id, login, verified_at
      `;
      return rows[0] ?? null;
    },

    async hasUserActivity(userId) {
      const rows = await sql`
        SELECT (
          EXISTS (SELECT 1 FROM tasks_pg WHERE owner_user_id = ${userId}::bigint) OR
          EXISTS (SELECT 1 FROM agents WHERE owner_user_id = ${userId}::bigint) OR
          EXISTS (SELECT 1 FROM user_wallets WHERE user_id = ${userId}::bigint) OR
          EXISTS (SELECT 1 FROM sessions WHERE user_id = ${userId}::bigint)
        ) AS active
      `;
      return Boolean(rows[0]?.active);
    },

    async createSession(row) {
      await sql`
        INSERT INTO sessions
          (session_id, session_hash, user_id, login, created_at, expires_at,
           auth_method, csrf_hash)
        VALUES
          (${row.session_id}, ${row.session_hash}, ${row.user_id}, ${row.login},
           ${row.created_at}, ${row.expires_at}, ${row.auth_method},
           ${row.csrf_hash})
      `;
    },

    async getSession({ tokenHash, rawToken, now }) {
      const rows = await sql`
        SELECT session_id, session_hash, user_id, login, expires_at,
               auth_method, csrf_hash
        FROM sessions
        WHERE (
          session_hash = ${tokenHash} OR
          (session_hash IS NULL AND session_id = ${rawToken})
        )
          AND (expires_at IS NULL OR expires_at > ${now})
        ORDER BY (session_hash = ${tokenHash}) DESC
        LIMIT 1
      `;
      return rows[0] ?? null;
    },

    async deleteSession(sessionId) {
      await sql`DELETE FROM sessions WHERE session_id = ${sessionId}`;
    },

    async setSessionCsrf(sessionId, csrfHash) {
      await sql`
        UPDATE sessions
        SET csrf_hash = ${csrfHash}
        WHERE session_id = ${sessionId}
      `;
    },

    async hitRateLimit(key, windowStart, limit) {
      const rows = await sql`
        INSERT INTO auth_rate_limits (rate_key, window_start, count)
        VALUES (${key}, ${windowStart}, 1)
        ON CONFLICT (rate_key) DO UPDATE SET
          count = CASE
            WHEN auth_rate_limits.window_start = EXCLUDED.window_start
              THEN auth_rate_limits.count + 1
            ELSE 1
          END,
          window_start = EXCLUDED.window_start
        RETURNING count, window_start
      `;
      const count = Number(rows[0]?.count ?? 0);
      return { count, limited: count > limit };
    },
  };
}
