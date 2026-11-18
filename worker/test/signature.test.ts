import { describe, expect, it } from "vitest";
import {
  computeHmacSha256,
  parseSignatureHeader,
  timingSafeEqual,
  verifyWebhookSignature,
} from "../src/lib/signature";

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

describe("computeHmacSha256", () => {
  // RFC 4231 test case 1: key = 20 bytes of 0x0b, data = "Hi There".
  it("matches the published HMAC-SHA256 test vector", async () => {
    const key = "\x0b".repeat(20);
    const digest = await computeHmacSha256(key, "Hi There");
    expect(toHex(digest)).toBe(
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    );
  });
});

describe("parseSignatureHeader", () => {
  it("accepts a valid header", () => {
    const parsed = parseSignatureHeader(`sha256=${"ab".repeat(32)}`);
    expect(parsed).toHaveLength(32);
    expect(parsed?.[0]).toBe(0xab);
  });

  it("rejects malformed headers", () => {
    expect(parseSignatureHeader(null)).toBeNull();
    expect(parseSignatureHeader("sha1=abcdef")).toBeNull();
    expect(parseSignatureHeader("sha256=not-hex")).toBeNull();
    expect(parseSignatureHeader(`sha256=${"ab".repeat(31)}`)).toBeNull();
  });
});

describe("verifyWebhookSignature", () => {
  it("accepts a correctly signed body", async () => {
    const secret = "a-github-webhook-secret";
    const body = new TextEncoder().encode('{"action":"opened"}');
    const signature = `sha256=${toHex(await computeHmacSha256(secret, body))}`;
    expect(await verifyWebhookSignature(secret, body, signature)).toBe(true);
  });

  it("rejects a body signed with the wrong secret", async () => {
    const body = new TextEncoder().encode('{"action":"opened"}');
    const signature = `sha256=${toHex(await computeHmacSha256("wrong", body))}`;
    expect(await verifyWebhookSignature("right", body, signature)).toBe(false);
  });

  it("rejects a missing secret or header", async () => {
    const body = new TextEncoder().encode("{}");
    expect(await verifyWebhookSignature(undefined, body, "sha256=" + "00".repeat(32))).toBe(
      false,
    );
    expect(await verifyWebhookSignature("secret", body, null)).toBe(false);
  });
});

describe("timingSafeEqual", () => {
  it("compares byte arrays", () => {
    expect(timingSafeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
    expect(timingSafeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
    expect(timingSafeEqual(new Uint8Array([1]), new Uint8Array([1, 2]))).toBe(false);
  });
});
