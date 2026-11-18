import type { ScanRequest, ScanMode } from "../types";

type Obj = Record<string, unknown>;

function asObject(value: unknown): Obj | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Obj)
    : null;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function isMerged(value: unknown): boolean {
  return value === true;
}

function repositoryFrom(payload: Obj): ScanRequest["repository"] | null {
  const repo = asObject(payload.repository);
  if (!repo) return null;
  const fullName = asString(repo.full_name);
  const name = asString(repo.name);
  const ownerObj = asObject(repo.owner);
  const owner = asString(ownerObj?.login) ?? asString(ownerObj?.name);
  if (!fullName || !name || !owner) return null;
  const installation = asObject(payload.installation);
  return {
    fullName,
    owner,
    name,
    installationId: asNumber(installation?.id),
  };
}

/** Only 40/64-char hexadecimal SHAs are accepted. Prevents shell/URL injection downstream. */
function validSha(value: unknown): string | undefined {
  const sha = asString(value);
  return sha && /^[0-9a-fA-F]{40}([0-9a-fA-F]{24})?$/.test(sha) ? sha.toLowerCase() : undefined;
}

export interface ClassifyOptions {
  /** Repositories we must never dispatch to (loop prevention). */
  ignoreRepositories?: string[];
  /** GitHub's x-github-delivery header, used for correlating logs. */
  deliveryId?: string;
}

/**
 * Turn a GitHub webhook into a runner request, or `null` when the event should
 * be ignored. Configuration (`.osv-pulse.yml`) is deliberately *not* read here:
 * the edge router stays stateless and the runner is the single source of truth.
 */
export function classifyEvent(
  event: string,
  payload: unknown,
  options: ClassifyOptions = {},
): ScanRequest | null {
  const body = asObject(payload);
  if (!body) return null;
  const repository = repositoryFrom(body);
  if (!repository) return null;
  if (options.ignoreRepositories?.includes(repository.fullName.toLowerCase())) return null;

  const deliveryId =
    options.deliveryId ?? asString(body.delivery_id) ?? asString(body.delivery);
  const action = asString(body.action);
  const triggeredAt = new Date().toISOString();
  const pusher =
    asString(asObject(body.pusher)?.name) ?? asString(asObject(body.sender)?.login);

  if (event === "pull_request") {
    const pr = asObject(body.pull_request);
    if (!pr) return null;
    const number = asNumber(pr.number);
    const head = asObject(pr.head);
    const base = asObject(pr.base);
    if (!number || !head || !base) return null;

    let mode: ScanMode | null = null;
    let headSha: string | undefined;
    if (action === "closed" && isMerged(pr.merged)) {
      mode = "merge";
      headSha = validSha(pr.merge_commit_sha) ?? validSha(head.sha);
    } else if (action === "opened" || action === "synchronize" || action === "reopened") {
      mode = "pr";
      headSha = validSha(head.sha);
    }
    if (!mode || !headSha) return null;

    return {
      source: "osv-pulse",
      mode,
      event,
      action,
      deliveryId,
      repository,
      headSha,
      baseSha: validSha(base.sha),
      pr: {
        number,
        headRef: asString(head.ref) ?? "",
        baseRef: asString(base.ref) ?? "",
      },
      pusher,
      triggeredAt,
    };
  }

  if (event === "push") {
    if (body.deleted === true) return null;
    const headSha = validSha(body.after);
    if (!headSha) return null;
    const ref = asString(body.ref) ?? "";
    const branch = ref.startsWith("refs/heads/") ? ref.slice("refs/heads/".length) : ref;
    return {
      source: "osv-pulse",
      mode: "push",
      event,
      action,
      deliveryId,
      repository,
      headSha,
      baseSha: validSha(body.before),
      ref,
      branch,
      pusher,
      triggeredAt,
    };
  }

  return null;
}
