// Cloudflare Pages Functions — /api/*.
//
// Static preview needs no env at module load. A Functions deployment without
// BACKEND returns a typed 503 on backend-dependent routes; static assets are
// still served independently. Worker-owned auth is the default; AUTH_MODE=proxy
// is the explicit rollback. Worker reads cover /api/me, owned agents,
// leaderboard, task reads (TASKS_MODE=neon), and schema.

import { handleMeRequest } from "../_lib/auth/me.js";
import { handleSchema } from "../_lib/schema.js";
import { createAgentReadMiddleware } from "../_lib/agents/read-agents.js";
import { createLeaderboardMiddleware } from "../_lib/agents/leaderboard.js";
import { createTaskReadMiddleware } from "../_lib/tasks/read-task.js";
import { handleOpenTasksRequest } from "../_lib/tasks/open-tasks.js";
import { proxyRequest } from "../_lib/proxy.js";

const agentRead = createAgentReadMiddleware();
const leaderboardRead = createLeaderboardMiddleware();
const taskRead = createTaskReadMiddleware();

export const onRequest = async (context) => {
    const request = context?.request;
    if (!request) {
        return new Response(
            JSON.stringify({ success: false, error: { code: "PROXY_CONFIG_ERROR", message: "The request is unavailable." } }),
            { status: 500, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } },
        );
    }
    const mode = String(context?.env?.AUTH_MODE ?? "worker");
    const path = new URL(request.url).pathname;
    // Session visibility is Cloudflare-owned for wallet auth. Keep other
    // API reads behind their explicit mode gates.
    if (path === "/api/me" && request.method === "GET") {
        return handleMeRequest(context);
    }
    if (mode === "worker" && new URL(request.url).pathname === "/api/schema") {
        return handleSchema(request);
    }
    if (mode === "worker" && request.method === "GET") {
        const leaderboardResponse = await leaderboardRead(context);
        if (leaderboardResponse) return leaderboardResponse;
        const agentResponse = await agentRead(context);
        if (agentResponse) return agentResponse;
        if (String(context?.env?.TASKS_MODE ?? "proxy") === "neon") {
            if (new URL(request.url).pathname === "/api/tasks/open") {
                return handleOpenTasksRequest(context);
            }
            const taskResponse = await taskRead(context);
            if (taskResponse) return taskResponse;
        }
    }
    return proxyRequest(context);
};
