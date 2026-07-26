/**
 * Support/feedback/privacy/breach reports. Stored directly in D1 rather
 * than routed through a transactional email provider — one fewer external
 * dependency and secret to manage. email_status stays 'not_configured' so
 * nothing implies a send that will never happen. The operator reads new
 * tickets with:
 *
 *   SELECT * FROM support_tickets WHERE status = 'open' ORDER BY id DESC;
 */
import { Account } from './auth';
import { Env, audit, ipHash, json, rateLimit } from './security';

const CATEGORIES = new Set(['support', 'feedback', 'privacy', 'breach']);
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function generateRef(): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I
  const bytes = crypto.getRandomValues(new Uint8Array(6));
  let code = '';
  for (const b of bytes) code += alphabet[b % alphabet.length];
  return `WN-${code}`;
}

export async function handleSupport(request: Request, env: Env, user: Account | null): Promise<Response> {
  const ip = await ipHash(request, env);
  if (!(await rateLimit(env.DB, `support:${ip}`, 5, 3600))) {
    return json({ error: 'Too many messages sent from this network. Try again later.' }, 429);
  }

  const body = (await request.json().catch(() => ({}))) as {
    category?: string;
    replyTo?: string;
    subject?: string;
    message?: string;
  };

  const category = String(body.category ?? '');
  const replyTo = String(body.replyTo ?? '').trim();
  const subject = String(body.subject ?? '').trim().slice(0, 150);
  const message = String(body.message ?? '').trim().slice(0, 5000);

  if (!CATEGORIES.has(category)) return json({ error: 'Choose a valid category.' }, 400);
  if (!EMAIL_RE.test(replyTo)) return json({ error: 'Enter a valid reply-to email address.' }, 400);
  if (subject.length < 3) return json({ error: 'Give it a short subject.' }, 400);
  if (message.length < 10) return json({ error: 'Say a bit more about what happened.' }, 400);

  const ref = generateRef();
  await env.DB.prepare(
    `INSERT INTO support_tickets (ref, user_id, category, reply_to, subject, body)
     VALUES (?, ?, ?, ?, ?, ?)`,
  )
    .bind(ref, user?.id ?? null, category, replyTo, subject, message)
    .run();

  await audit(env.DB, `support.${category}`, { userId: user?.id, detail: ref, ipHash: ip });

  return json({ ok: true, message: `Thanks — reference ${ref}. We'll reply to ${replyTo}.` });
}
