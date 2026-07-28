/**
 * Cross-cutting security helpers: bindings, response hardening, session
 * cookies, origin/CSRF checks, rate limiting, keyed IP hashing, and audit
 * logging. Nothing here is chat- or auth-specific.
 */

export interface Env {
  AI: Ai;
  ASSETS: { fetch: (request: Request) => Promise<Response> };
  DB: D1Database;
  MEDIA: R2Bucket;
  APP_ORIGIN: string;
  /** HMAC key for IP hashing. Rotating it resets throttling. Wrangler secret. */
  APP_SECRET: string;
  /** Optional. Deep Think falls back to the normal model if unset. Wrangler secret. */
  NVIDIA_API_KEY?: string;
}

export const SESSION_COOKIE = '__Host-session';
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days

export function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
}

/** Applies baseline security headers to every response the Worker returns. */
export function harden(response: Response): Response {
  const headers = new Headers(response.headers);
  headers.set(
    'content-security-policy',
    "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  );
  headers.set('x-content-type-options', 'nosniff');
  headers.set('x-frame-options', 'DENY');
  headers.set('referrer-policy', 'no-referrer');
  headers.set('strict-transport-security', 'max-age=63072000; includeSubDomains; preload');
  headers.set('permissions-policy', 'camera=(), microphone=(), geolocation=()');
  return new Response(response.body, { status: response.status, headers });
}

/**
 * State-changing requests must carry an Origin header that matches our own
 * origin exactly. Cookies are already SameSite=Strict, so this is
 * defense-in-depth rather than the only CSRF barrier.
 */
export function originAllowed(request: Request, appOrigin: string): boolean {
  const origin = request.headers.get('origin');
  if (!origin) return false;
  return origin === appOrigin;
}

/* ---------------------------------------------------------------- crypto */

function toHex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function randomToken(bytes = 32): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return toHex(arr.buffer);
}

async function hmac(key: string, message: string): Promise<string> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(message));
  return toHex(sig);
}

/** Session tokens are stored server-side only as their HMAC — a leaked DB row can't be replayed as a cookie. */
export async function hashToken(env: Env, token: string): Promise<string> {
  return hmac(env.APP_SECRET, `session:${token}`);
}

/** Keyed IP hash for throttling/audit, so raw IPs are never persisted. */
export async function ipHash(request: Request, env: Env): Promise<string> {
  const ip = request.headers.get('cf-connecting-ip') ?? 'unknown';
  return hmac(env.APP_SECRET, `ip:${ip}`);
}

/* --------------------------------------------------------------- cookies */

export function sessionCookie(token: string, maxAgeSeconds = SESSION_TTL_SECONDS): string {
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAgeSeconds}`;
}

export function clearSessionCookie(): string {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

export function readSessionToken(request: Request): string | null {
  const header = request.headers.get('cookie');
  if (!header) return null;
  for (const part of header.split(';')) {
    const [name, ...rest] = part.trim().split('=');
    if (name === SESSION_COOKIE) return rest.join('=');
  }
  return null;
}

export { SESSION_TTL_SECONDS };

/* ---------------------------------------------------------------- limits */

/**
 * Sliding-window rate limit backed by the `auth_attempts` log table: counts
 * rows in `bucket` newer than the window, then records this attempt.
 * Returns true if the call is allowed. Buckets encode the action, e.g.
 * "signin:<iphash>", so unrelated actions never share a counter.
 */
export async function rateLimit(
  db: D1Database,
  bucket: string,
  limit: number,
  windowSeconds: number,
): Promise<boolean> {
  const cutoff = new Date(Date.now() - windowSeconds * 1000).toISOString();
  const row = await db
    .prepare('SELECT COUNT(*) AS n FROM auth_attempts WHERE bucket = ? AND at > ?')
    .bind(bucket, cutoff)
    .first<{ n: number }>();
  await db.prepare('INSERT INTO auth_attempts (bucket) VALUES (?)').bind(bucket).run();
  return (row?.n ?? 0) < limit;
}

export async function audit(
  db: D1Database,
  action: string,
  opts?: { userId?: number; detail?: string; ipHash?: string },
): Promise<void> {
  await db
    .prepare('INSERT INTO audit_log (user_id, action, detail, ip_hash) VALUES (?, ?, ?, ?)')
    .bind(opts?.userId ?? null, action, opts?.detail ?? null, opts?.ipHash ?? null)
    .run();
}
