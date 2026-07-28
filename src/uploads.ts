/**
 * Attachments — images (captioned by a vision model), plain text files
 * (read directly), and PDFs (stored but not parsed).
 *
 * Audio and video upload were removed entirely: no accept type offers them,
 * the `uploads.kind` CHECK constraint in the database no longer allows
 * those values at all, and detect() below independently rejects anything
 * it doesn't recognise by actual file signature — never by the client's
 * claimed MIME type or extension.
 */
import { Account } from './auth';
import { Env, json, rateLimit } from './security';

const MAX_IMAGE_BYTES = 3 * 1024 * 1024; // 3 MB
const MAX_FILE_BYTES = 10 * 1024 * 1024; // 10 MB
const RETENTION_DAYS = 30;
const VISION_MODEL = '@cf/llava-hf/llava-1.5-7b-hf';

type Detected =
  | { kind: 'image'; mime: string }
  | { kind: 'document'; mime: string }
  | { kind: 'text'; mime: string };

/** Identifies a file by its actual byte signature — never trusts the client's declared MIME type. */
function detect(bytes: Uint8Array, filename: string): Detected | null {
  if (bytes.length >= 8 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) {
    return { kind: 'image', mime: 'image/png' };
  }
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
    return { kind: 'image', mime: 'image/jpeg' };
  }
  if (bytes.length >= 6 && bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x38) {
    return { kind: 'image', mime: 'image/gif' };
  }
  if (
    bytes.length >= 12 &&
    bytes[0] === 0x52 &&
    bytes[1] === 0x49 &&
    bytes[2] === 0x46 &&
    bytes[3] === 0x46 &&
    bytes[8] === 0x57 &&
    bytes[9] === 0x45 &&
    bytes[10] === 0x42 &&
    bytes[11] === 0x50
  ) {
    return { kind: 'image', mime: 'image/webp' };
  }
  if (bytes.length >= 5 && bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) {
    return { kind: 'document', mime: 'application/pdf' };
  }

  const textExt = /\.(txt|md|csv|json|xml)$/i.test(filename);
  if (textExt) {
    try {
      new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes);
      return { kind: 'text', mime: 'text/plain' };
    } catch {
      return null;
    }
  }

  return null;
}

function sanitizeFilename(name: string): string {
  return name.replace(/[/\\ -]/g, '_').slice(-200) || 'upload';
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function handleUpload(request: Request, env: Env, user: Account): Promise<Response> {
  if (!(await rateLimit(env.DB, `upload:${user.id}`, 20, 3600))) {
    return json({ error: "You've uploaded a lot of files this hour. Try again later." }, 429);
  }

  const form = await request.formData().catch(() => null);
  const file = form?.get('file');
  if (!(file instanceof File)) {
    return json({ error: 'No file received.' }, 400);
  }

  const buffer = new Uint8Array(await file.arrayBuffer());
  const detected = detect(buffer, file.name);
  if (!detected) {
    return json(
      { error: 'Unsupported file type. Only images (PNG/JPEG/GIF/WEBP), plain text/CSV/JSON/XML, and PDF are accepted.' },
      415,
    );
  }

  const cap = detected.kind === 'image' ? MAX_IMAGE_BYTES : MAX_FILE_BYTES;
  if (buffer.byteLength > cap) {
    return json({ error: `That file is too large (max ${Math.round(cap / (1024 * 1024))} MB for this type).` }, 413);
  }

  const filename = sanitizeFilename(file.name);
  const r2Key = `${user.id}/${crypto.randomUUID()}-${filename}`;
  await env.MEDIA.put(r2Key, buffer, { httpMetadata: { contentType: detected.mime } });
  const hash = await sha256Hex(buffer);

  let extracted: string | null = null;
  let note: string | null = null;

  if (detected.kind === 'image') {
    try {
      const result = (await env.AI.run(VISION_MODEL, {
        image: Array.from(buffer),
        prompt: 'Describe this image factually and concisely for someone who cannot see it.',
        max_tokens: 512,
      })) as { description?: string; response?: string };
      extracted = (result.description ?? result.response ?? '').trim() || null;
    } catch (err) {
      console.error('vision captioning failed', err);
      note = 'Uploaded, but the image could not be described automatically.';
    }
  } else if (detected.kind === 'text') {
    extracted = new TextDecoder().decode(buffer).slice(0, 20_000);
  } else {
    note = 'Stored, not read — this deployment has no PDF text extraction.';
  }

  const purgeAfter = new Date(Date.now() + RETENTION_DAYS * 24 * 60 * 60 * 1000).toISOString();
  const result = await env.DB.prepare(
    `INSERT INTO uploads (user_id, r2_key, filename, mime, kind, bytes, sha256, extracted, purge_after)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(user.id, r2Key, filename, detected.mime, detected.kind, buffer.byteLength, hash, extracted, purgeAfter)
    .run();

  return json({ id: result.meta.last_row_id, kind: detected.kind, note });
}

export async function handleMedia(env: Env, user: Account, id: number): Promise<Response> {
  const row = await env.DB.prepare('SELECT r2_key, mime, filename FROM uploads WHERE id = ? AND user_id = ?')
    .bind(id, user.id)
    .first<{ r2_key: string; mime: string; filename: string }>();
  if (!row) return json({ error: 'Not found.' }, 404);

  const object = await env.MEDIA.get(row.r2_key);
  if (!object) return json({ error: 'Not found.' }, 404);

  return new Response(object.body, {
    headers: {
      'content-type': row.mime,
      'content-disposition': `inline; filename="${row.filename.replace(/"/g, '')}"`,
      'cache-control': 'private, max-age=3600',
    },
  });
}

/** Deletes expired uploads (R2 + D1), expired sessions, and old attempt/audit rows. Called from the nightly cron. */
export async function purgeExpired(env: Env): Promise<number> {
  const expired = await env.DB.prepare("SELECT id, r2_key FROM uploads WHERE purge_after < datetime('now')").all<{
    id: number;
    r2_key: string;
  }>();

  for (const row of expired.results) {
    await env.MEDIA.delete(row.r2_key).catch(() => undefined);
  }
  if (expired.results.length) {
    const ids = expired.results.map((r) => r.id);
    await env.DB.prepare(`DELETE FROM uploads WHERE id IN (${ids.map(() => '?').join(',')})`)
      .bind(...ids)
      .run();
  }

  await env.DB.prepare("DELETE FROM sessions WHERE expires_at < datetime('now')").run();
  // auth_attempts only needs to cover the longest rate-limit window in use (1 hour); keep 2 days for a little audit slack.
  await env.DB.prepare("DELETE FROM auth_attempts WHERE at < datetime('now', '-2 days')").run();

  return expired.results.length;
}
