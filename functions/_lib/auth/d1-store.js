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
  };
}
