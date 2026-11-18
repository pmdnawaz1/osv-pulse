const encoder = new TextEncoder();

/** Constant-time comparison. Length mismatch is not a secret and fails fast. */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Parse the `sha256=<64 hex chars>` value of x-hub-signature-256. */
export function parseSignatureHeader(header: string | null | undefined): Uint8Array | null {
  if (!header) return null;
  const value = header.trim();
  if (!value.startsWith("sha256=")) return null;
  const hex = value.slice(7).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) return null;
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

export async function computeHmacSha256(
  secret: string,
  body: ArrayBuffer | Uint8Array | string,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  let payload: ArrayBuffer;
  if (typeof body === "string") {
    payload = encoder.encode(body).buffer;
  } else if (body instanceof Uint8Array) {
    const copy = new Uint8Array(body.byteLength);
    copy.set(body);
    payload = copy.buffer;
  } else {
    payload = body;
  }
  const signature = await crypto.subtle.sign("HMAC", key, payload);
  return new Uint8Array(signature);
}

/**
 * Verify a GitHub webhook signature against the *raw* request body.
 * Never re-serialize the JSON body: whitespace changes invalidate the HMAC.
 */
export async function verifyWebhookSignature(
  secret: string | undefined,
  rawBody: ArrayBuffer | Uint8Array,
  signatureHeader: string | null | undefined,
): Promise<boolean> {
  if (!secret) return false;
  const provided = parseSignatureHeader(signatureHeader);
  if (!provided) return false;
  const expected = await computeHmacSha256(secret, rawBody);
  return timingSafeEqual(provided, expected);
}
