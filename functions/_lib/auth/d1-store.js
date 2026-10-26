// Cloudflare D1-backed AuthStore for Cloudflare-only wallet login.
//
// This store is selected only when a D1 `DB` binding exists. It uses the
// isolated auth schema in migrations/0009_d1_auth.sql. No Blitz endpoint is
// called and no secret/private material is stored here.

function value(value) {
  return value === undefined ? null : value;
}

export function createD1Store(db) {
  if (!db || typeof db.prepare !== "function") {
    throw new Error("D1 DB binding is not configured");
  }

  async function first(sql, params = []) {
    return db.prepare(sql).bind(...params).first();
  }
  async function all(sql, params = []) {
    const result = await db.prepare(sql).bind(...params).all();
    return result.results ?? [];
  }
  async function run(sql, params = []) {
    return db.prepare(sql).bind(...params).run();
  }

  return {
    async createNonce(row) {
      await run(
        `INSERT INTO wallet_nonces
           (nonce_hash, address, purpose, user_id, message, domain, chain_id,
            issued_at, expires_at, consumed_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
        [
          row.nonce_hash,
          row.address,
          row.purpose,
          value(row.user_id),
          row.message,
          row.domain,
          row.chain_id,
          row.issued_at,
          row.expires_at,
        ],
      );
    },

    async consumeNonce(nonceHash, now) {
      return first(
        `UPDATE wallet_nonces
         SET consumed_at = ?
         WHERE nonce_hash = ? AND consumed_at IS NULL AND expires_at > ?
         RETURNING nonce_hash, address, purpose, user_id, message, domain,
                   chain_id, issued_at, expires_at, consumed_at`,
        [now, nonceHash, now],
      );
    },

    async findIdentity(provider, subject) {
      return first(
        `SELECT provider, subject, user_id, login, verified_at
         FROM auth_identities WHERE provider = ? AND subject = ? LIMIT 1`,
        [provider, subject],
      );
    },

    async insertIdentity(row) {
      const result = await run(
        `INSERT OR IGNORE INTO auth_identities
           (provider, subject, user_id, login, verified_at)
         VALUES (?, ?, ?, ?, ?)`,
        [row.provider, row.subject, String(row.user_id), row.login, row.verified_at],
      );
      if (!result?.meta?.changes) return null;
      return {
        provider: row.provider,
        subject: row.subject,
        user_id: String(row.user_id),
        login: row.login,
        verified_at: row.verified_at,
      };
    },

    async hasUserActivity(userId) {
      const row = await first(
        `SELECT COUNT(*) AS n FROM sessions WHERE user_id = ? AND
           (expires_at IS NULL OR expires_at > ?)`,
        [String(userId), Math.floor(Date.now() / 1000)],
      );
      return Number(row?.n ?? 0) > 0;
    },

    async getUserWallet(userId) {
      return first(
        `SELECT pubkey FROM user_wallets WHERE user_id = ? LIMIT 1`,
        [String(userId)],
      );
    },

    async createSession(row) {
      await run(
        `INSERT INTO sessions
           (session_id, session_hash, user_id, login, created_at, expires_at,
            auth_method, csrf_hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          row.session_id,
          value(row.session_hash),
          String(row.user_id),
          row.login,
          row.created_at,
          value(row.expires_at),
          value(row.auth_method),
          value(row.csrf_hash),
        ],
      );
    },

    async getSession({ tokenHash, rawToken, now }) {
      return first(
        `SELECT session_id, session_hash, user_id, login, created_at, expires_at,
                auth_method, csrf_hash
         FROM sessions
         WHERE (session_hash = ? OR (session_hash IS NULL AND session_id = ?))
           AND (expires_at IS NULL OR expires_at > ?)
         LIMIT 1`,
        [tokenHash, rawToken, now],
      );
    },

    async deleteSession(sessionId) {
      await run(`DELETE FROM sessions WHERE session_id = ?`, [sessionId]);
    },

    async setSessionCsrf(sessionId, csrfHash) {
      await run(`UPDATE sessions SET csrf_hash = ? WHERE session_id = ?`, [
        csrfHash,
        sessionId,
      ]);
    },

    async hitRateLimit(key, windowStart, limit) {
      const row = await first(
        `INSERT INTO auth_rate_limits (key, window_start, count)
         VALUES (?, ?, 1)
         ON CONFLICT(key) DO UPDATE SET
           count = CASE WHEN auth_rate_limits.window_start = excluded.window_start
                        THEN auth_rate_limits.count + 1 ELSE 1 END,
           window_start = excluded.window_start
         RETURNING count, window_start`,
        [key, windowStart],
      );
      const count = Number(row?.count ?? 0);
      return { count, limited: count > limit };
    },

    async getProvisioning(userId) {
      try {
        return await first(
          `SELECT state, updated_at FROM wallet_provision_requests
           WHERE user_id = ? LIMIT 1`,
          [String(userId)],
        );
      } catch {
        return null;
      }
    },

    async enqueueProvisioning(userId, now) {
      try {
        const result = await run(
          `INSERT INTO wallet_provision_requests
             (user_id, state, attempts, next_attempt_at, requested_at, updated_at)
           VALUES (?, 'pending', 0, ?, ?, ?)
           ON CONFLICT(user_id) DO NOTHING`,
          [String(userId), now, now, now],
        );
        return Boolean(result?.meta?.changes);
      } catch {
        return false;
      }
    },

    // ---- Cloudflare D1 application projection (no signing authority) ----

    async listAgents(ownerUserId) {
      return all(
        `SELECT agent_id, owner_user_id, name, status, schema_version,
                wallet_address, auth_public_key, created_at, updated_at
         FROM agents WHERE owner_user_id = ?
         ORDER BY updated_at DESC, agent_id ASC`,
        [String(ownerUserId)],
      );
    },

    async getAgent(ownerUserId, agentId) {
      return first(
        `SELECT agent_id, owner_user_id, name, status, schema_version,
                wallet_address, auth_public_key, created_at, updated_at
         FROM agents WHERE owner_user_id = ? AND agent_id = ? LIMIT 1`,
        [String(ownerUserId), String(agentId)],
      );
    },

    async createAgent(ownerUserId, agentId, name, now) {
      await run(
        `INSERT INTO agents
           (agent_id, owner_user_id, name, status, schema_version,
            wallet_address, auth_public_key, policy_json, created_at, updated_at)
         VALUES (?, ?, ?, 'draft', 1, NULL, NULL, '{}', ?, ?)`,
        [String(agentId), String(ownerUserId), name, now, now],
      );
      return this.getAgent(ownerUserId, agentId);
    },

    async renameAgent(ownerUserId, agentId, name, now) {
      await run(
        `UPDATE agents SET name = ?, updated_at = ?
         WHERE owner_user_id = ? AND agent_id = ?`,
        [name, now, String(ownerUserId), String(agentId)],
      );
      return this.getAgent(ownerUserId, agentId);
    },

    async deleteAgent(ownerUserId, agentId) {
      const result = await run(
        `DELETE FROM agents WHERE owner_user_id = ? AND agent_id = ? AND status = 'draft'`,
        [String(ownerUserId), String(agentId)],
      );
      return Boolean(result?.meta?.changes);
    },

    async setAgentStatus(ownerUserId, agentId, to, now) {
      const current = await this.getAgent(ownerUserId, agentId);
      if (!current) return { notFound: true };
      const allowed = {
        draft: ["active"],
        active: ["paused", "disabled"],
        paused: ["active", "disabled"],
        disabled: [],
      }[String(current.status)] || [];
      if (!allowed.includes(to)) return { invalid: true, current: current.status };
      await run(
        `UPDATE agents SET status = ?, updated_at = ?
         WHERE owner_user_id = ? AND agent_id = ?`,
        [to, now, String(ownerUserId), String(agentId)],
      );
      return { agent: await this.getAgent(ownerUserId, agentId) };
    },

    async getAgentPolicy(ownerUserId, agentId) {
      const row = await first(
        `SELECT policy_json FROM agents WHERE owner_user_id = ? AND agent_id = ? LIMIT 1`,
        [String(ownerUserId), String(agentId)],
      );
      if (!row) return null;
      try {
        return JSON.parse(row.policy_json || "{}");
      } catch {
        return {};
      }
    },

    async setAgentPolicy(ownerUserId, agentId, policy, now) {
      const result = await run(
        `UPDATE agents SET policy_json = ?, updated_at = ?
         WHERE owner_user_id = ? AND agent_id = ?`,
        [JSON.stringify(policy), now, String(ownerUserId), String(agentId)],
      );
      if (!result?.meta?.changes) return null;
      return this.getAgentPolicy(ownerUserId, agentId);
    },

    async getLeaderboard(ownerUserId) {
      return all(
        `SELECT a.agent_id, a.name, a.status,
                COUNT(p.intent_id) AS total_intent_count,
                COALESCE(SUM(CASE WHEN p.status = 'confirmed' THEN 1 ELSE 0 END), 0) AS confirmed_payment_count,
                COALESCE(SUM(CASE WHEN p.status = 'confirmed' THEN p.amount_kelvin ELSE 0 END), 0) AS confirmed_payment_volume_kelvin,
                MAX(CASE WHEN p.status = 'confirmed' THEN p.updated_at ELSE NULL END) AS last_confirmed_at,
                COALESCE(SUM(CASE WHEN p.status = 'pending' THEN 1 ELSE 0 END), 0) AS pending_count,
                COALESCE(SUM(CASE WHEN p.status = 'failed' THEN 1 ELSE 0 END), 0) AS failed_count,
                COALESCE(SUM(CASE WHEN p.status = 'unknown' THEN 1 ELSE 0 END), 0) AS unknown_count,
                COALESCE(SUM(CASE WHEN p.status = 'reconciled' THEN 1 ELSE 0 END), 0) AS reconciled_count
         FROM agents a LEFT JOIN payment_intents p ON p.agent_id = a.agent_id
         WHERE a.owner_user_id = ?
         GROUP BY a.agent_id, a.name, a.status
         ORDER BY confirmed_payment_volume_kelvin DESC, last_confirmed_at DESC,
                  confirmed_payment_count DESC, a.agent_id ASC`,
        [String(ownerUserId)],
      );
    },

    async listOpenTasks(viewerId) {
      return all(
        `SELECT task_id, title, status, reward_kelvin, owner_name, worker_name, created_at
         FROM tasks WHERE status = 'open'
         ORDER BY created_at DESC, task_id ASC LIMIT 200`,
        [],
      );
    },

    async listTasks(viewerId) {
      if (viewerId === null || viewerId === undefined) {
        return [];
      }
      return all(
        `SELECT * FROM tasks WHERE owner_user_id = ? OR worker_id = ?
         ORDER BY created_at DESC, task_id ASC LIMIT 200`,
        [String(viewerId), String(viewerId)],
      );
    },

    async getTask(taskId) {
      return first(`SELECT * FROM tasks WHERE task_id = ? LIMIT 1`, [String(taskId)]);
    },

    async createTask(row) {
      await run(
        `INSERT INTO tasks
           (task_id, owner_user_id, owner_name, agent_id, title, description,
            acceptance_criteria, reward_kelvin, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)`,
        [
          row.task_id, String(row.owner_user_id), row.owner_name || "",
          value(row.agent_id), row.title, row.description || "",
          row.acceptance_criteria || "", row.reward_kelvin, row.created_at, row.created_at,
        ],
      );
      return this.getTask(row.task_id);
    },

    async claimTask(taskId, userId, login, address, now) {
      const result = await run(
        `UPDATE tasks SET status = 'inprogress', worker_id = ?, worker_name = ?,
                payout_address = ?, claimed_at = ?, updated_at = ?
         WHERE task_id = ? AND status = 'open'`,
        [String(userId), login || "", address || null, now, now, String(taskId)],
      );
      if (!result?.meta?.changes) return { conflict: true };
      return { task: await this.getTask(taskId) };
    },

    async submitTask(taskId, userId, url, notes, attachments, now) {
      const result = await run(
        `UPDATE tasks SET status = 'underreview', submission_url = ?,
                submission_notes = ?, attachments_json = ?, submitted_at = ?, updated_at = ?
         WHERE task_id = ? AND status = 'inprogress' AND worker_id = ?`,
        [url || "", notes || "", JSON.stringify(attachments || []), now, now, String(taskId), String(userId)],
      );
      if (!result?.meta?.changes) return { conflict: true };
      return { task: await this.getTask(taskId) };
    },

    async cancelTask(taskId, userId, now) {
      const result = await run(
        `UPDATE tasks SET status = 'cancelled', updated_at = ?
         WHERE task_id = ? AND status = 'open' AND owner_user_id = ?`,
        [now, String(taskId), String(userId)],
      );
      return Boolean(result?.meta?.changes);
    },

    async reviewTask(taskId, userId, decision, notes, now) {
      const next = decision === "reject" ? "rejected" : "revisionrequested";
      const result = await run(
        `UPDATE tasks SET status = ?, review_notes = ?, reviewed_at = ?, updated_at = ?
         WHERE task_id = ? AND owner_user_id = ?
           AND status IN ('submitted', 'underreview')`,
        [next, notes || "", now, now, String(taskId), String(userId)],
      );
      if (!result?.meta?.changes) return { conflict: true };
      return { task: await this.getTask(taskId) };
    },

    async getAgentStats(ownerUserId, agentId) {
      return first(
        `SELECT a.agent_id, a.name, a.status,
                COUNT(p.intent_id) AS total_intent_count,
                COALESCE(SUM(CASE WHEN p.status = 'confirmed' THEN 1 ELSE 0 END), 0) AS confirmed_payment_count,
                COALESCE(SUM(CASE WHEN p.status = 'confirmed' THEN p.amount_kelvin ELSE 0 END), 0) AS confirmed_payment_volume_kelvin
         FROM agents a LEFT JOIN payment_intents p ON p.agent_id = a.agent_id
         WHERE a.owner_user_id = ? AND a.agent_id = ?
         GROUP BY a.agent_id, a.name, a.status`,
        [String(ownerUserId), String(agentId)],
      );
    },

    async listAgentActivity(ownerUserId, agentId, limit = 50) {
      return all(
        `SELECT event_id, task_id, at, kind, actor_user_id, detail
         FROM task_events WHERE task_id IN
           (SELECT task_id FROM tasks WHERE owner_user_id = ? OR worker_id = ?)
         ORDER BY at DESC, event_id DESC LIMIT ?`,
        [String(ownerUserId), String(ownerUserId), Math.min(Number(limit) || 50, 200)],
      );
    },
  };
}
