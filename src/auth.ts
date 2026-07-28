/**
 * Accounts: signup/signin/signout, password hashing, sessions, and the
 * account-management endpoints (export, change password, delete).
 */
import {
  Env,
  audit,
  clearSessionCookie,
  hashToken,
  ipHash,
  json,
  randomToken,
  rateLimit,
  readSessionToken,
  sessionCookie,
  SESSION_TTL_SECONDS,
} from './security';

export interface Account {
  id: number;
  username: string;
  email: string;
}

const PBKDF2_ITERATIONS = 210_000;
const USERNAME_RE = /^[a-z0-9_-]{3,32}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MIN_PASSWORD_LENGTH = 12;
const MAX_PASSWORD_LENGTH = 200;
const PRIVACY_NOTICE_VERSION = '2026-07-26';

/** After this many failed attempts on one account within the window, it locks. */
const FAILURE_LOCK_THRESHOLD = 8;
const LOCK_WINDOW_SECONDS = 15 * 60;
const LOCK_MINUTES = 15;

/* -------------------------------------------------------------- hashing */

function toB64(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function fromB64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function deriveBits(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, [
    'deriveBits',
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: salt as BufferSource, iterations, hash: 'SHA-256' },
    keyMaterial,
    256,
  );
  return new Uint8Array(bits);
}

async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await deriveBits(password, salt, PBKDF2_ITERATIONS);
  return `pbkdf2$${PBKDF2_ITERATIONS}$${toB64(salt)}$${toB64(hash)}`;
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// A well-formed dummy hash so a signin against a nonexistent account still
// pays the full PBKDF2 cost — without this, response time alone would tell
// an attacker which usernames exist.
const DUMMY_HASH = `pbkdf2$${PBKDF2_ITERATIONS}$${toB64(new Uint8Array(16))}$${toB64(new Uint8Array(32))}`;

async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false;
  const iterations = Number(parts[1]);
  if (!Number.isInteger(iterations) || iterations < 1) return false;
  const salt = fromB64(parts[2]);
  const expected = fromB64(parts[3]);
  const actual = await deriveBits(password, salt, iterations);
  return timingSafeEqual(actual, expected);
}

/* --------------------------------------------------------------- session */

export async function currentUser(request: Request, env: Env): Promise<Account | null> {
  const token = readSessionToken(request);
  if (!token) return null;
  const tokenHash = await hashToken(env, token);

  const row = await env.DB.prepare(
    `SELECT u.id, u.username, u.email
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ? AND s.expires_at > datetime('now')`,
  )
    .bind(tokenHash)
    .first<Account>();
  return row ?? null;
}

async function createSession(request: Request, env: Env, userId: number, ip: string): Promise<string> {
  const token = randomToken();
  const tokenHash = await hashToken(env, token);
  const expiresAt = new Date(Date.now() + SESSION_TTL_SECONDS * 1000).toISOString();
  const userAgent = request.headers.get('user-agent')?.slice(0, 256) ?? null;
  await env.DB.prepare(
    'INSERT INTO sessions (token_hash, user_id, expires_at, ip_hash, user_agent) VALUES (?, ?, ?, ?, ?)',
  )
    .bind(tokenHash, userId, expiresAt, ip, userAgent)
    .run();
  return token;
}

/* ----------------------------------------------------------------- signup */

export async function handleSignup(request: Request, env: Env): Promise<Response> {
  const ip = await ipHash(request, env);
  if (!(await rateLimit(env.DB, `signup:${ip}`, 5, 3600))) {
    return json({ error: 'Too many accounts created from this network. Try again later.' }, 429);
  }

  const body = (await request.json().catch(() => ({}))) as {
    username?: string;
    email?: string;
    password?: string;
    acceptedPrivacy?: boolean;
  };

  const username = String(body.username ?? '').trim().toLowerCase();
  const email = String(body.email ?? '').trim().toLowerCase();
  const password = String(body.password ?? '');

  if (!USERNAME_RE.test(username)) {
    return json({ error: 'Username must be 3-32 characters: lowercase letters, numbers, - or _.' }, 400);
  }
  if (!EMAIL_RE.test(email) || email.length > 254) {
    return json({ error: 'Enter a valid email address.' }, 400);
  }
  if (password.length < MIN_PASSWORD_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
    return json({ error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters.` }, 400);
  }
  if (body.acceptedPrivacy !== true) {
    return json({ error: 'You need to accept the collection notice to continue.' }, 400);
  }

  const existing = await env.DB.prepare('SELECT id FROM users WHERE username = ? OR email = ?')
    .bind(username, email)
    .first();
  if (existing) {
    return json({ error: 'That username or email is already registered.' }, 409);
  }

  const passwordHash = await hashPassword(password);
  const result = await env.DB.prepare(
    `INSERT INTO users (username, email, password_hash, privacy_notice_version, privacy_accepted_at)
     VALUES (?, ?, ?, ?, datetime('now'))`,
  )
    .bind(username, email, passwordHash, PRIVACY_NOTICE_VERSION)
    .run();

  const userId = result.meta.last_row_id as number;
  const token = await createSession(request, env, userId, ip);
  await audit(env.DB, 'auth.signup', { userId, ipHash: ip });

  return withCookie(json({ username, email }, 201), sessionCookie(token));
}

export async function handleSignin(request: Request, env: Env): Promise<Response> {
  const ip = await ipHash(request, env);
  if (!(await rateLimit(env.DB, `signin:${ip}`, 20, 900))) {
    return json({ error: 'Too many sign-in attempts from this network. Try again later.' }, 429);
  }

  const body = (await request.json().catch(() => ({}))) as { username?: string; password?: string };
  const identifier = String(body.username ?? '').trim().toLowerCase();
  const password = String(body.password ?? '');

  if (!identifier || !password) {
    return json({ error: 'Enter your username/email and password.' }, 400);
  }
  if (!(await rateLimit(env.DB, `signin:id:${identifier}`, 10, 900))) {
    return json({ error: 'Too many attempts for this account. Try again later.' }, 429);
  }

  const user = await env.DB.prepare(
    `SELECT id, username, email, password_hash, is_disabled,
            (locked_until IS NOT NULL AND locked_until > datetime('now')) AS locked
       FROM users WHERE username = ? OR email = ?`,
  )
    .bind(identifier, identifier)
    .first<Account & { password_hash: string; is_disabled: number; locked: number }>();

  if (!user) {
    await verifyPassword(password, DUMMY_HASH); // pay the same PBKDF2 cost as a real check
    await audit(env.DB, 'auth.signin.failed', { detail: 'unknown account', ipHash: ip });
    return json({ error: 'Incorrect username/email or password.' }, 401);
  }
  if (user.is_disabled) {
    await audit(env.DB, 'auth.signin.disabled', { userId: user.id, ipHash: ip });
    return json({ error: 'This account has been disabled. Contact support.' }, 403);
  }
  if (user.locked) {
    await audit(env.DB, 'auth.signin.locked', { userId: user.id, ipHash: ip });
    return json({ error: 'Too many failed attempts. Try again in a few minutes.' }, 423);
  }

  const ok = await verifyPassword(password, user.password_hash);
  if (!ok) {
    const underLimit = await rateLimit(env.DB, `signin:fail:${user.id}`, FAILURE_LOCK_THRESHOLD, LOCK_WINDOW_SECONDS);
    if (!underLimit) {
      await env.DB.prepare("UPDATE users SET locked_until = datetime('now', ?) WHERE id = ?")
        .bind(`+${LOCK_MINUTES} minutes`, user.id)
        .run();
      await audit(env.DB, 'auth.account_locked', { userId: user.id, ipHash: ip });
    }
    await audit(env.DB, 'auth.signin.failed', { userId: user.id, ipHash: ip });
    return json({ error: 'Incorrect username/email or password.' }, 401);
  }

  await env.DB.prepare("UPDATE users SET last_login_at = datetime('now') WHERE id = ?").bind(user.id).run();
  const token = await createSession(request, env, user.id, ip);
  await audit(env.DB, 'auth.signin.success', { userId: user.id, ipHash: ip });

  return withCookie(json({ username: user.username, email: user.email }), sessionCookie(token));
}

export async function handleSignout(request: Request, env: Env): Promise<Response> {
  const token = readSessionToken(request);
  if (token) {
    const tokenHash = await hashToken(env, token);
    await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(tokenHash).run();
  }
  return withCookie(json({ ok: true }), clearSessionCookie());
}

export async function handleSignoutAll(user: Account, env: Env): Promise<Response> {
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id).run();
  await audit(env.DB, 'auth.signout_all', { userId: user.id });
  return withCookie(json({ ok: true }), clearSessionCookie());
}

/* --------------------------------------------------------------- account */

export async function handleChangePassword(request: Request, env: Env, user: Account): Promise<Response> {
  const body = (await request.json().catch(() => ({}))) as { current?: string; next?: string };
  const current = String(body.current ?? '');
  const next = String(body.next ?? '');

  if (next.length < MIN_PASSWORD_LENGTH || next.length > MAX_PASSWORD_LENGTH) {
    return json({ error: `New password must be at least ${MIN_PASSWORD_LENGTH} characters.` }, 400);
  }

  const row = await env.DB.prepare('SELECT password_hash FROM users WHERE id = ?')
    .bind(user.id)
    .first<{ password_hash: string }>();
  if (!row || !(await verifyPassword(current, row.password_hash))) {
    return json({ error: 'Current password is incorrect.' }, 401);
  }

  const newHash = await hashPassword(next);
  await env.DB.prepare('UPDATE users SET password_hash = ? WHERE id = ?').bind(newHash, user.id).run();
  // Changing the password invalidates every other session; the caller keeps using this response's request,
  // but for safety we drop all sessions and let them sign back in.
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id).run();
  await audit(env.DB, 'auth.password_changed', { userId: user.id });

  return withCookie(json({ ok: true }), clearSessionCookie());
}

export async function handleDeleteAccount(request: Request, env: Env, user: Account): Promise<Response> {
  const body = (await request.json().catch(() => ({}))) as { confirm?: string; password?: string };
  const row = await env.DB.prepare('SELECT password_hash FROM users WHERE id = ?')
    .bind(user.id)
    .first<{ password_hash: string }>();
  if (
    body.confirm !== user.username ||
    !row ||
    !(await verifyPassword(String(body.password ?? ''), row.password_hash))
  ) {
    return json({ error: 'Type your exact username and correct password to confirm deletion.' }, 400);
  }

  const uploads = await env.DB.prepare('SELECT r2_key FROM uploads WHERE user_id = ?')
    .bind(user.id)
    .all<{ r2_key: string }>();
  for (const u of uploads.results) {
    await env.MEDIA.delete(u.r2_key).catch(() => undefined);
  }

  // D1's SQLite doesn't reliably enforce ON DELETE CASCADE across the HTTP
  // API, so dependent rows are removed explicitly rather than trusted to cascade.
  await env.DB.batch([
    env.DB.prepare('DELETE FROM messages WHERE user_id = ?').bind(user.id),
    env.DB.prepare('DELETE FROM memories WHERE user_id = ?').bind(user.id),
    env.DB.prepare('DELETE FROM uploads WHERE user_id = ?').bind(user.id),
    env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id),
    env.DB.prepare('DELETE FROM users WHERE id = ?').bind(user.id),
  ]);
  await audit(env.DB, 'auth.account_deleted', { userId: user.id });

  return withCookie(json({ ok: true }), clearSessionCookie());
}

export async function handleExport(env: Env, user: Account): Promise<Response> {
  const [account, messages, memories, uploads] = await Promise.all([
    env.DB.prepare('SELECT username, email, created_at FROM users WHERE id = ?').bind(user.id).first(),
    env.DB.prepare('SELECT role, content, created_at FROM messages WHERE user_id = ? ORDER BY id').bind(user.id).all(),
    env.DB.prepare('SELECT fact, created_at FROM memories WHERE user_id = ? ORDER BY id').bind(user.id).all(),
    env.DB.prepare('SELECT filename, kind, mime, bytes, created_at FROM uploads WHERE user_id = ? ORDER BY id')
      .bind(user.id)
      .all(),
  ]);

  const payload = {
    account,
    messages: messages.results,
    memories: memories.results,
    uploads: uploads.results,
    exported_at: new Date().toISOString(),
  };

  return new Response(JSON.stringify(payload, null, 2), {
    headers: {
      'content-type': 'application/json',
      'content-disposition': 'attachment; filename="warnetwork-export.json"',
    },
  });
}

/* ----------------------------------------------------------------- utils */

function withCookie(response: Response, cookie: string): Response {
  const headers = new Headers(response.headers);
  headers.append('set-cookie', cookie);
  return new Response(response.body, { status: response.status, headers });
}
