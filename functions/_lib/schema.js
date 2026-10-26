// Worker-owned GET /api/schema.
//
// The backend serves a static credential-storage schema document. This is
// public, has no database or signer dependency, and is safe to serve from the
// Worker. Keep the document byte-shape identical to
// src/schema/credentials.schema.json; tests assert the fields.
export const CREDENTIALS_SCHEMA = {
  schema_version: 2,
  description:
    "Agent credential storage using Argon2id hashing. Version 2 stores salt and argon2_hash fields. No plaintext credential persisted.",
  fields: {
    agent_id: "Canonical UUID of the agent",
    salt: "Hex-encoded random salt (16 bytes)",
    argon2_hash: "Hex-encoded Argon2id hash of the credential",
    created_at: "Unix timestamp when credential issued",
    updated_at: "Unix timestamp when last modified",
    revoked_at: "Optional timestamp when revoked (null if active)",
  },
};

export function handleSchema(request) {
  if (request.method !== "GET") {
    return new Response(
      JSON.stringify({
        success: false,
        error: { code: "METHOD_NOT_ALLOWED", message: "Method not allowed" },
      }),
      { status: 405, headers: { "content-type": "application/json; charset=utf-8" } },
    );
  }
  return new Response(JSON.stringify(CREDENTIALS_SCHEMA), {
    status: 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}
