// In-memory AuthStore used only by unit tests. It mirrors the production
// store's atomicity/conflict semantics closely enough to exercise the router.

export class MemoryAuthStore {
  constructor({ now = () => Math.floor(Date.now() / 1000) } = {}) {
    this.now = now;
    this.nonces = new Map();
    this.identities = new Map();
    this.sessions = new Map();
    this.rate = new Map();
    this.activity = new Set();
    this.wallets = new Map();
    this.calls = [];
  }

  async createNonce(row) {
    this.calls.push(["createNonce", row.nonce_hash]);
    if (this.nonces.has(row.nonce_hash)) throw new Error("nonce collision");
    this.nonces.set(row.nonce_hash, { ...row, consumed_at: null });
  }

  async consumeNonce(nonceHash, now) {
    this.calls.push(["consumeNonce", nonceHash]);
    const row = this.nonces.get(nonceHash);
    if (!row || row.consumed_at !== null || row.expires_at <= now) return null;
    row.consumed_at = now;
    return { ...row };
  }

  async findIdentity(provider, subject) {
    this.calls.push(["findIdentity", provider, subject]);
    return this.identities.get(`${provider}:${subject}`) ?? null;
  }

  async insertIdentity(row) {
    this.calls.push(["insertIdentity", row.provider, row.subject]);
    const key = `${row.provider}:${row.subject}`;
    if (this.identities.has(key)) return null;
    const value = { ...row };
    this.identities.set(key, value);
    return value;
  }

  async hasUserActivity(userId) {
    this.calls.push(["hasUserActivity", String(userId)]);
    return this.activity?.has(String(userId)) ?? false;
  }

  async getUserWallet(userId) {
    this.calls.push(["getUserWallet", String(userId)]);
    return this.wallets.get(String(userId)) ?? null;
  }

  async createSession(row) {
    this.calls.push(["createSession", row.session_id]);
    if (this.sessions.has(row.session_id)) throw new Error("session collision");
    this.sessions.set(row.session_id, { ...row });
  }

  async getSession({ tokenHash, rawToken, now }) {
    this.calls.push(["getSession", tokenHash]);
    for (const row of this.sessions.values()) {
      const hashMatch = row.session_hash && row.session_hash === tokenHash;
      const rawMatch = !row.session_hash && row.session_id === rawToken;
      if ((hashMatch || rawMatch) && (row.expires_at == null || row.expires_at > now)) {
        return { ...row };
      }
    }
    return null;
  }

  async deleteSession(sessionId) {
    this.calls.push(["deleteSession", sessionId]);
    this.sessions.delete(sessionId);
  }

  async setSessionCsrf(sessionId, csrfHash) {
    this.calls.push(["setSessionCsrf", sessionId]);
    const row = this.sessions.get(sessionId);
    if (row) row.csrf_hash = csrfHash;
  }

  async hitRateLimit(key, windowStart, limit) {
    this.calls.push(["hitRateLimit", key]);
    const current = this.rate.get(key);
    if (!current || current.window_start !== windowStart) {
      this.rate.set(key, { window_start: windowStart, count: 1 });
      return { count: 1, limited: false };
    }
    current.count += 1;
    return { count: current.count, limited: current.count > limit };
  }
}
