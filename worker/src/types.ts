export type ScanMode = "pr" | "merge" | "push";

export interface ScanRequest {
  /** Marks payloads produced by this worker. */
  source: "osv-pulse";
  mode: ScanMode;
  event: "pull_request" | "push";
  action?: string;
  /** GitHub delivery GUID, useful for correlating logs. */
  deliveryId?: string;
  repository: {
    fullName: string;
    owner: string;
    name: string;
    installationId?: number;
  };
  headSha: string;
  baseSha?: string;
  pr?: {
    number: number;
    headRef: string;
    baseRef: string;
  };
  ref?: string;
  branch?: string;
  pusher?: string;
  triggeredAt: string;
}

export interface Env {
  /** GitHub App webhook secret (wrangler secret). */
  GITHUB_WEBHOOK_SECRET: string;
  /** Fine-grained PAT with Contents: read/write on the runner repo (wrangler secret). */
  RUNNER_PAT: string;
  /** Owner (org or user) of the central runner repo (wrangler secret). */
  RUNNER_OWNER: string;
  /** Name of the central runner repo (wrangler secret). */
  RUNNER_REPO: string;
  /** Optional override for the repository_dispatch event type. */
  DISPATCH_EVENT_TYPE?: string;
}
