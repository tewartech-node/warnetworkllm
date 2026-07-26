/**
 * Deep Think — an opt-in path to NVIDIA's hosted Nemotron 3 Ultra
 * (build.nvidia.com), used instead of the Workers AI model for a single
 * message at a time.
 *
 * This is deliberately NOT the default. It leaves Cloudflare's edge for a
 * single centralised API, adds real round-trip latency, and depends on a
 * free-tier rate limit (roughly 40 requests/minute per NVIDIA account) that
 * Cloudflare has no visibility into. If the key is missing, unset, or the
 * call fails, the caller falls back to the normal model — Deep Think should
 * degrade gracefully, never break the chat.
 */
import { Env } from './security';

export const NEMOTRON_MODEL = 'nvidia/nemotron-3-ultra-550b-a55b';
const NVIDIA_ENDPOINT = 'https://integrate.api.nvidia.com/v1/chat/completions';

/** Generous but bounded — this is a slow model on a remote endpoint. */
const REQUEST_TIMEOUT_MS = 45_000;

interface ChatTurn {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

export interface NemotronResult {
  ok: true;
  stream: ReadableStream<Uint8Array>;
}

export interface NemotronError {
  ok: false;
  reason: string;
}

/**
 * Streams a chat completion from Nemotron and re-shapes it to match the
 * Workers AI SSE format the client already parses: lines of
 * `data: {"response": "<token>"}`. This means the frontend needs zero
 * awareness of which backend answered — only which endpoint the Worker
 * decided to call.
 */
export async function runNemotron(
  env: Env,
  messages: ChatTurn[],
): Promise<NemotronResult | NemotronError> {
  if (!env.NVIDIA_API_KEY) {
    return { ok: false, reason: 'Deep Think is not configured on this deployment yet.' };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  let upstream: Response;
  try {
    upstream = await fetch(NVIDIA_ENDPOINT, {
      method: 'POST',
      signal: controller.signal,
      headers: {
        Authorization: `Bearer ${env.NVIDIA_API_KEY}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        model: NEMOTRON_MODEL,
        messages,
        temperature: 0.6,
        top_p: 0.95,
        max_tokens: 2048,
        stream: true,
        chat_template_kwargs: { enable_thinking: true },
      }),
    });
  } catch (err) {
    clearTimeout(timeout);
    const aborted = err instanceof Error && err.name === 'AbortError';
    return {
      ok: false,
      reason: aborted
        ? 'Nemotron took too long to respond. Try again, or turn Deep Think off for this message.'
        : "Couldn't reach NVIDIA's API. Try again in a moment.",
    };
  }
  clearTimeout(timeout);

  if (!upstream.ok || !upstream.body) {
    const status = upstream.status;
    const detail =
      status === 429
        ? "NVIDIA's free tier is rate-limited — wait a minute and try again."
        : status === 401
          ? 'The Nemotron API key is invalid or has been revoked.'
          : `Nemotron returned an error (${status}).`;
    return { ok: false, reason: detail };
  }

  return { ok: true, stream: reshapeToWorkersAiFormat(upstream.body) };
}

/**
 * Nemotron speaks OpenAI-style SSE: `data: {"choices":[{"delta":{"content":
 * "...", "reasoning_content": "..."}}]}`. We fold both fields into the same
 * `response` key Workers AI emits, so one client-side parser handles either
 * backend. The reasoning trace is prefixed distinctly so the UI can dim it.
 */
function reshapeToWorkersAiFormat(upstream: ReadableStream<Uint8Array>): ReadableStream<Uint8Array> {
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  let buf = '';

  return upstream.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        buf += decoder.decode(chunk, { stream: true });
        const lines = buf.split('\n');
        buf = lines.pop() ?? '';

        for (const line of lines) {
          const t = line.trim();
          if (!t.startsWith('data:')) continue;
          const data = t.slice(5).trim();
          if (data === '[DONE]') {
            controller.enqueue(encoder.encode('data: [DONE]\n\n'));
            continue;
          }
          try {
            const parsed = JSON.parse(data);
            const delta = parsed.choices?.[0]?.delta ?? {};
            if (delta.reasoning_content) {
              controller.enqueue(
                encoder.encode(`data: ${JSON.stringify({ reasoning: delta.reasoning_content })}\n\n`),
              );
            }
            if (delta.content) {
              controller.enqueue(
                encoder.encode(`data: ${JSON.stringify({ response: delta.content })}\n\n`),
              );
            }
          } catch {
            /* ignore malformed keep-alive fragments */
          }
        }
      },
    }),
  );
}
