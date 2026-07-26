/* Warnetwork LLM — client */

const $ = (sel) => document.querySelector(sel);
const state = { mode: 'signin', user: null, turns: [], attachments: [], oldestId: null, busy: false, deepThink: false };

/* ------------------------------------------------------------ helpers */

async function api(path, { method = 'GET', body, form } = {}) {
  const init = { method, credentials: 'same-origin', headers: {} };
  if (form) init.body = form;
  else if (body !== undefined) {
    init.headers['content-type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  const res = await fetch(path, init);
  const type = res.headers.get('content-type') ?? '';
  const data = type.includes('json') ? await res.json() : null;
  if (!res.ok) throw new Error(data?.error ?? `Request failed (${res.status})`);
  return data;
}

function setStrip(stateName, label, meta) {
  const strip = $('#strip');
  strip.dataset.state = stateName;
  $('#strip-state').textContent = label;
  if (meta !== undefined) $('#strip-meta').textContent = meta;
}

function showError(el, message) {
  el.textContent = message;
  el.hidden = !message;
}

/* --------------------------------------------------------------- gate */

document.querySelectorAll('.seg-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    state.mode = btn.dataset.mode;
    document.querySelectorAll('.seg-btn').forEach((b) => b.classList.toggle('is-on', b === btn));
    const signup = state.mode === 'signup';
    document.querySelectorAll('.only-signup').forEach((el) => (el.hidden = !signup));
    $('#lbl-id-hint').hidden = signup;
    $('#auth-submit').textContent = signup ? 'Create account' : 'Sign in';
    $('#auth-form').password.autocomplete = signup ? 'new-password' : 'current-password';
    showError($('#auth-error'), '');
  });
});

$('#auth-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = e.target;
  const submit = $('#auth-submit');
  submit.disabled = true;
  showError($('#auth-error'), '');

  try {
    const payload = { username: f.username.value, password: f.password.value };
    if (state.mode === 'signup') {
      payload.email = f.email.value;
      payload.acceptedPrivacy = f.acceptedPrivacy.checked;
    }
    state.user = await api(state.mode === 'signup' ? '/api/signup' : '/api/signin', {
      method: 'POST',
      body: payload,
    });
    await enterApp();
  } catch (err) {
    showError($('#auth-error'), err.message);
  } finally {
    submit.disabled = false;
  }
});

$('#open-notice').addEventListener('click', showNotice);
$('#gate-support').addEventListener('click', () => {
  showModal(
    'Contact support',
    `<p>You can send a support message without signing in. Include the username you're
     trying to reach and what happens when you try.</p>`,
  );
});

/* ---------------------------------------------------------------- app */

async function enterApp() {
  $('#gate').hidden = true;
  $('#app').hidden = false;
  $('#acct-name').textContent = state.user.username;
  $('#acct-email').textContent = state.user.email;
  $('#support-form').replyTo.value = state.user.email;
  setStrip('ready', 'Ready', 'No attachments');
  await loadHistory();
}

document.querySelectorAll('.tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('is-on', t === tab));
    document.querySelectorAll('.panel').forEach((p) =>
      p.classList.toggle('is-on', p.dataset.panel === tab.dataset.tab),
    );
  });
});

/* ------------------------------------------------------------ history */

async function loadHistory(before) {
  const data = await api(`/api/history${before ? `?before=${before}` : ''}`);
  const thread = $('#thread');
  const anchor = thread.scrollHeight;

  for (const m of [...data.messages].reverse()) {
    const node = renderMessage(m.role, m.content, m.filename ? { filename: m.filename, kind: m.kind } : null);
    thread.insertBefore(node, $('#load-more').nextSibling);
  }

  if (!before) {
    state.turns = data.messages.map((m) => ({ role: m.role, content: m.content }));
    thread.scrollTop = thread.scrollHeight;
  } else {
    thread.scrollTop = thread.scrollHeight - anchor;
  }

  state.oldestId = data.oldestId;
  $('#load-more').hidden = !data.hasMore;
}

$('#load-more').addEventListener('click', () => state.oldestId && loadHistory(state.oldestId));

function renderMessage(role, content, file) {
  const wrap = document.createElement('div');
  wrap.className = `msg ${role}`;
  const who = document.createElement('div');
  who.className = 'msg-who';
  who.textContent = role === 'user' ? state.user.username : 'Assistant';
  const body = document.createElement('div');
  body.className = 'msg-body';
  body.textContent = content;
  wrap.append(who, body);
  if (file) {
    const tag = document.createElement('div');
    tag.className = 'msg-file';
    tag.textContent = `${file.kind} · ${file.filename}`;
    wrap.append(tag);
  }
  return wrap;
}

/* --------------------------------------------------------- attachments */

$('#deep-think-btn').addEventListener('click', () => {
  state.deepThink = !state.deepThink;
  $('#deep-think-btn').setAttribute('aria-pressed', String(state.deepThink));
  $('#deep-think-note').hidden = !state.deepThink;
});

$('#attach-btn').addEventListener('click', () => {
  const menu = $('#attach-menu');
  menu.hidden = !menu.hidden;
  $('#attach-btn').setAttribute('aria-expanded', String(!menu.hidden));
});

document.querySelectorAll('#attach-menu button').forEach((btn) => {
  btn.addEventListener('click', () => {
    const input = $('#file-input');
    input.accept = btn.dataset.accept;
    input.click();
    $('#attach-menu').hidden = true;
    $('#attach-btn').setAttribute('aria-expanded', 'false');
  });
});

$('#file-input').addEventListener('change', async (e) => {
  const file = e.target.files?.[0];
  e.target.value = '';
  if (!file) return;

  const entry = { name: file.name, status: 'pending', id: null };
  state.attachments.push(entry);
  drawTray();
  setStrip('busy', 'Reading file', file.name);

  try {
    const form = new FormData();
    form.append('file', file);
    const result = await api('/api/upload', { method: 'POST', form });
    entry.id = result.id;
    entry.status = 'ready';
    entry.kind = result.kind;
    entry.note = result.note;
    setStrip('ready', 'Ready', `${state.attachments.length} attached`);
    if (result.note) showModal('Uploaded', `<p><strong>${file.name}</strong></p><p>${result.note}</p>`);
  } catch (err) {
    entry.status = 'failed';
    entry.error = err.message;
    setStrip('error', 'Upload failed', err.message);
  }
  drawTray();
});

function drawTray() {
  const tray = $('#tray');
  tray.innerHTML = '';
  tray.hidden = state.attachments.length === 0;
  state.attachments.forEach((a, i) => {
    const chip = document.createElement('span');
    chip.className = `chip ${a.status === 'ready' ? '' : a.status}`;
    chip.textContent = a.status === 'pending' ? `${a.name} …` : a.name;
    const x = document.createElement('button');
    x.type = 'button';
    x.textContent = '×';
    x.setAttribute('aria-label', `Remove ${a.name}`);
    x.addEventListener('click', () => {
      state.attachments.splice(i, 1);
      drawTray();
      setStrip('ready', 'Ready', state.attachments.length ? `${state.attachments.length} attached` : 'No attachments');
    });
    chip.append(x);
    tray.append(chip);
  });
}

/* ---------------------------------------------------------------- chat */

const input = $('#input');
input.addEventListener('input', () => {
  input.style.height = 'auto';
  input.style.height = `${Math.min(input.scrollHeight, 160)}px`;
});
input.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey && window.matchMedia('(min-width: 768px)').matches) {
    e.preventDefault();
    $('#composer').requestSubmit();
  }
});

$('#composer').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (state.busy) return;

  const text = input.value.trim();
  const ready = state.attachments.filter((a) => a.status === 'ready');
  if (!text && !ready.length) return;

  const prompt = text || 'Describe what I have attached.';
  state.busy = true;
  $('#send').disabled = true;
  input.value = '';
  input.style.height = 'auto';

  const thread = $('#thread');
  thread.append(renderMessage('user', prompt, ready[0] ? { filename: ready[0].name, kind: ready[0].kind } : null));
  thread.scrollTop = thread.scrollHeight;

  const wasDeepThink = state.deepThink;
  state.turns.push({ role: 'user', content: prompt });
  const bubble = renderMessage('assistant', '', null);
  thread.append(bubble);
  const target = bubble.querySelector('.msg-body');
  setStrip('busy', wasDeepThink ? 'Deep Think' : 'Thinking', wasDeepThink ? 'Nemotron 3 Ultra' : '');

  // Toggle resets the moment the message is sent, not after the reply lands —
  // it governs this one message, and shouldn't stay on by accident.
  state.deepThink = false;
  $('#deep-think-btn').setAttribute('aria-pressed', 'false');
  $('#deep-think-note').hidden = true;

  let reasoningEl = null;

  try {
    const res = await fetch('/api/chat', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        messages: state.turns.slice(-24),
        attachmentIds: ready.map((a) => a.id),
        deepThink: wasDeepThink,
      }),
    });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error ?? 'Request failed.');

    const modelUsed = res.headers.get('x-model-used') ?? 'llama';
    if (modelUsed === 'nemotron') {
      const who = bubble.querySelector('.msg-who');
      const tag = document.createElement('span');
      tag.className = 'msg-model';
      tag.textContent = 'Nemotron 3 Ultra';
      who.append(tag);
    }

    setStrip('busy', 'Streaming', modelUsed === 'nemotron' ? 'Nemotron 3 Ultra' : '');
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    let full = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      const lines = buf.split('\n');
      buf = lines.pop() ?? '';
      for (const line of lines) {
        const t = line.trim();
        if (!t.startsWith('data:')) continue;
        const payload = t.slice(5).trim();
        if (payload === '[DONE]') continue;
        try {
          const parsed = JSON.parse(payload);
          if (parsed.reasoning) {
            if (!reasoningEl) {
              reasoningEl = document.createElement('div');
              reasoningEl.className = 'msg-reasoning';
              target.before(reasoningEl);
            }
            reasoningEl.textContent = (reasoningEl.textContent || '') + parsed.reasoning;
            thread.scrollTop = thread.scrollHeight;
          }
          if (parsed.response) {
            full += parsed.response;
            target.textContent = full;
            thread.scrollTop = thread.scrollHeight;
          }
        } catch { /* keep-alive */ }
      }
    }

    state.turns.push({ role: 'assistant', content: full });
    state.attachments = [];
    drawTray();
    setStrip('ready', 'Ready', 'No attachments');
  } catch (err) {
    target.textContent = err.message;
    setStrip('error', 'Failed', err.message);
  } finally {
    state.busy = false;
    $('#send').disabled = false;
  }
});

/* ------------------------------------------------------------- support */

$('#support-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = e.target;
  showError($('#support-error'), '');
  $('#support-ok').hidden = true;

  try {
    const result = await api('/api/support', {
      method: 'POST',
      body: {
        category: f.category.value,
        replyTo: f.replyTo.value,
        subject: f.subject.value,
        message: f.message.value,
      },
    });
    $('#support-ok').textContent = result.message;
    $('#support-ok').hidden = false;
    f.subject.value = '';
    f.message.value = '';
  } catch (err) {
    showError($('#support-error'), err.message);
  }
});

/* ------------------------------------------------------------- account */

$('#btn-export').addEventListener('click', () => { window.location.href = '/api/account/export'; });

$('#btn-signout').addEventListener('click', async () => {
  await api('/api/signout', { method: 'POST' });
  location.reload();
});

$('#btn-revoke').addEventListener('click', async () => {
  await api('/api/account/sessions', { method: 'DELETE' });
  location.reload();
});

$('#btn-notice').addEventListener('click', showNotice);

$('#btn-delete').addEventListener('click', () => {
  showModal(
    'Delete my account',
    `<p>This removes your messages, saved notes and uploaded files. It cannot be undone.</p>
     <label class="field"><span>Type your username to confirm</span><input id="del-confirm" autocapitalize="none"></label>
     <label class="field"><span>Password</span><input id="del-pw" type="password"></label>
     <p class="form-error" id="del-error" hidden></p>`,
    [
      { label: 'Delete permanently', primary: true, onClick: async () => {
        try {
          await api('/api/account', {
            method: 'DELETE',
            body: { confirm: $('#del-confirm').value, password: $('#del-pw').value },
          });
          location.reload();
        } catch (err) {
          showError($('#del-error'), err.message);
        }
      } },
      { label: 'Cancel', onClick: closeModal },
    ],
  );
});

/* --------------------------------------------------------------- modal */

function showModal(title, html, actions = [{ label: 'Close', onClick: closeModal }]) {
  $('#modal-title').textContent = title;
  $('#modal-body').innerHTML = html;
  const bar = $('#modal-actions');
  bar.innerHTML = '';
  for (const a of actions) {
    const btn = document.createElement('button');
    btn.className = a.primary ? 'btn-primary' : 'btn-ghost';
    btn.textContent = a.label;
    btn.addEventListener('click', a.onClick);
    bar.append(btn);
  }
  $('#modal').hidden = false;
}

function closeModal() { $('#modal').hidden = true; }

$('#modal').addEventListener('click', (e) => { if (e.target.id === 'modal') closeModal(); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });

function showNotice() {
  showModal(
    'Collection notice',
    `<h4>What's collected</h4>
     <p>Your username, email address, a hash of your password, the messages you send and
     receive, notes you save, files you upload, and a keyed hash of your IP address used
     only to slow down abuse. Raw IP addresses are not stored.</p>

     <h4>Why</h4>
     <p>To run your account, keep your conversation available to you, analyse the files you
     choose to attach, answer your support messages, and protect the service from misuse.</p>

     <h4>Where it goes</h4>
     <p>Data is held on Cloudflare infrastructure and may be processed outside Australia.
     Message text and uploaded images are sent to Cloudflare Workers AI for inference — and,
     only when you tap Deep Think, that one message is sent to NVIDIA's hosted API instead.
     <strong>Don't upload anything you would not want processed overseas.</strong></p>

     <h4>How long it's kept</h4>
     <p>Uploaded files are deleted automatically 30 days after upload. Messages and notes are
     kept until you delete your account.</p>

     <h4>Your choices</h4>
     <p>You can download everything held about you, correct it by editing your notes, or
     delete your account outright from the Account tab. If something looks wrong, use the
     Support tab and choose the privacy category.</p>`,
  );
}

/* ------------------------------------------------------------- startup */

(async () => {
  try {
    state.user = await api('/api/me');
    await enterApp();
  } catch {
    $('#gate').hidden = false;
  }
})();
