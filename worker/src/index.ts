import { dispatchScan } from "./lib/dispatch";
import { classifyEvent } from "./lib/events";
import { verifyWebhookSignature } from "./lib/signature";
import type { Env } from "./types";

const MAX_BODY_BYTES = 1024 * 1024;

function json(data: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...headers },
  });
}

function missingConfig(env: Env): string[] {
  const required: (keyof Env)[] = [
    "GITHUB_WEBHOOK_SECRET",
    "RUNNER_PAT",
    "RUNNER_OWNER",
    "RUNNER_REPO",
  ];
  return required.filter((key) => !env[key]);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/health" && request.method === "GET") {
      return json({ ok: true, service: "osv-pulse" });
    }

    if (request.method !== "POST") {
      return json({ ok: false, error: "method_not_allowed" }, 405, { allow: "POST" });
    }

    const missing = missingConfig(env);
    if (missing.length > 0) {
      console.error("osv-pulse: missing configuration", missing.join(","));
      return json({ ok: false, error: "server_misconfigured", missing }, 500);
    }

    const declaredLength = Number(request.headers.get("content-length") ?? 0);
    if (declaredLength > MAX_BODY_BYTES) {
      return json({ ok: false, error: "payload_too_large" }, 413);
    }

    const rawBody = await request.arrayBuffer();
    if (rawBody.byteLength > MAX_BODY_BYTES) {
      return json({ ok: false, error: "payload_too_large" }, 413);
    }

    const validSignature = await verifyWebhookSignature(
      env.GITHUB_WEBHOOK_SECRET,
      rawBody,
      request.headers.get("x-hub-signature-256"),
    );
    if (!validSignature) {
      return json({ ok: false, error: "invalid_signature" }, 401);
    }

    let payload: unknown;
    try {
      payload = JSON.parse(new TextDecoder().decode(rawBody));
    } catch {
      return json({ ok: false, error: "invalid_json" }, 400);
    }

    const event = request.headers.get("x-github-event") ?? "";
    if (event === "ping") {
      return json({ ok: true, ignored: "ping" });
    }

    const runnerFullName = `${env.RUNNER_OWNER}/${env.RUNNER_REPO}`.toLowerCase();
    const scan = classifyEvent(event, payload, {
      ignoreRepositories: [runnerFullName],
      deliveryId: request.headers.get("x-github-delivery") ?? undefined,
    });
    if (!scan) {
      return json({ ok: true, ignored: "unsupported_event", event });
    }

    console.log(
      `osv-pulse: dispatch ${scan.mode} ${scan.repository.fullName}@${scan.headSha}` +
        ` delivery=${scan.deliveryId ?? "-"}`,
    );
    return dispatchScan(env, scan);
  },
};
