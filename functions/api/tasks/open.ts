// Cloudflare Pages Functions — GET /api/tasks/open.
//
// Read-only Worker-owned route only when TASKS_MODE=neon. All task mutations
// still proxy to the backend. This avoids moving payment/signer-sensitive task
// actions without a reviewed signer boundary.

import { handleOpenTasksRequest } from "../../_lib/tasks/open-tasks.js";
import { proxyRequest } from "../../_lib/proxy.js";

export const onRequest = async (context) => {
    const request = context?.request;
    if (!request) return proxyRequest(context);
    const mode = String(context?.env?.TASKS_MODE ?? "proxy");
    if (request.method === "GET" && mode === "neon") {
        return handleOpenTasksRequest(context);
    }
    return proxyRequest(context);
};
