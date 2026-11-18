import { describe, expect, it } from "vitest";
import { classifyEvent } from "../src/lib/events";

const repository = {
  full_name: "acme/shop",
  name: "shop",
  owner: { login: "acme" },
};

function pullRequestPayload(overrides: Record<string, unknown> = {}) {
  return {
    action: "opened",
    repository,
    installation: { id: 123 },
    pull_request: {
      number: 42,
      merged: false,
      merge_commit_sha: null,
      head: { sha: "a".repeat(40), ref: "feature/fix" },
      base: { sha: "b".repeat(40), ref: "main" },
    },
    ...overrides,
  };
}

describe("classifyEvent", () => {
  it("classifies PR opens, synchronizes and reopens as diff scans", () => {
    for (const action of ["opened", "synchronize", "reopened"]) {
      const result = classifyEvent("pull_request", pullRequestPayload({ action }));
      expect(result?.mode).toBe("pr");
      expect(result?.action).toBe(action);
      expect(result?.pr?.number).toBe(42);
    }
  });

  it("classifies a merged PR as a full scan", () => {
    const payload = pullRequestPayload({
      action: "closed",
      pull_request: {
        number: 42,
        merged: true,
        merge_commit_sha: "c".repeat(40),
        head: { sha: "a".repeat(40), ref: "feature/fix" },
        base: { sha: "b".repeat(40), ref: "main" },
      },
    });
    const result = classifyEvent("pull_request", payload);
    expect(result?.mode).toBe("merge");
    expect(result?.headSha).toBe("c".repeat(40));
  });

  it("ignores a closed-but-unmerged PR", () => {
    const payload = pullRequestPayload({ action: "closed" });
    expect(classifyEvent("pull_request", payload)).toBeNull();
  });

  it("classifies a push and extracts the branch", () => {
    const result = classifyEvent("push", {
      ref: "refs/heads/production",
      before: "b".repeat(40),
      after: "d".repeat(40),
      deleted: false,
      repository,
      pusher: { name: "alice" },
    });
    expect(result?.mode).toBe("push");
    expect(result?.branch).toBe("production");
    expect(result?.headSha).toBe("d".repeat(40));
  });

  it("ignores deleted branches and unknown events", () => {
    expect(
      classifyEvent("push", {
        ref: "refs/heads/old",
        after: "0".repeat(40),
        deleted: true,
        repository,
      }),
    ).toBeNull();
    expect(classifyEvent("issues", { repository })).toBeNull();
  });

  it("never dispatches to the runner repository itself", () => {
    const payload = pullRequestPayload({
      repository: {
        full_name: "acme/osv-pulse-runner",
        name: "osv-pulse-runner",
        owner: { login: "acme" },
      },
    });
    expect(
      classifyEvent("pull_request", payload, {
        ignoreRepositories: ["acme/osv-pulse-runner"],
      }),
    ).toBeNull();
  });

  it("rejects invalid commit SHAs", () => {
    const payload = pullRequestPayload();
    const bad = {
      ...payload,
      pull_request: {
        ...(payload.pull_request as Record<string, unknown>),
        head: { sha: "not-a-sha; rm -rf /", ref: "feature/fix" },
      },
    };
    expect(classifyEvent("pull_request", bad)).toBeNull();
  });
});
