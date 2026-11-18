import type { Env, ScanRequest } from "../types";

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

/** Send the scan request to the single central runner repository. */
export async function dispatchScan(env: Env, request: ScanRequest): Promise<Response> {
  const owner = encodeURIComponent(env.RUNNER_OWNER);
  const repo = encodeURIComponent(env.RUNNER_REPO);
  const url = `https://api.github.com/repos/${owner}/${repo}/dispatches`;

  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: {
        authorization: `Bearer ${env.RUNNER_PAT}`,
        accept: "application/vnd.github+json",
        "content-type": "application/json",
        "x-github-api-version": "2022-11-28",
        "user-agent": "osv-pulse-edge-router",
      },
      body: JSON.stringify({
        event_type: env.DISPATCH_EVENT_TYPE ?? "osv-pulse-scan",
        client_payload: request,
      }),
    });
  } catch (error) {
    return json(
      { ok: false, error: "dispatch_network_error", detail: String(error) },
      502,
    );
  }

  if (!response.ok) {
    const detail = (await response.text()).slice(0, 500);
    return json(
      { ok: false, error: "dispatch_failed", status: response.status, detail },
      502,
    );
  }

  return json({
    ok: true,
    mode: request.mode,
    repository: request.repository.fullName,
    headSha: request.headSha,
    deliveryId: request.deliveryId ?? null,
  });
}
