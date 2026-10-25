'use strict';
/*
 * «Дневник массажиста» — сервер.
 * Express + хранилище S3 (Timeweb). Данные лежат в одном файле store.json.
 *
 * Принципы безопасности данных (после урока с потерей данных в «Задачнике»):
 *  1. Если файл с данными не удалось ПРОЧИТАТЬ — сервер ничего не записывает и ничего не «засевает».
 *     Пустое состояние создаётся только если файла точно нет (NoSuchKey).
 *  2. Каждая запись идёт строго по очереди (без одновременных перезаписей).
 *  3. Версии: клиент обязан прислать версию, с которой работал. Устаревшая версия → 409,
 *     так что телефон со старыми/пустыми данными не затрёт свежие.
 *  4. Защита от «усыхания»: запись, которая уменьшает список более чем вдвое, отклоняется
 *     (кроме восстановления из копии — тогда сначала делается снимок).
 *  5. Ежедневная копия в S3 (backups/) и на почту (Resend).
 */
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const PORT = process.env.PORT || 3000;
const KEYS = ['mj-clients', 'mj-revenue', 'mj-tasks', 'mj-offdays'];
const ARRAY_GUARD_KEYS = ['mj-clients', 'mj-revenue', 'mj-tasks'];

/* ---------- пароли и сессии ---------- */
const PASS = {
  karina: process.env.APP_PASSWORD_KARINA || process.env.APP_PASSWORD || '',
  husband: process.env.APP_PASSWORD_HUSBAND || process.env.APP_PASSWORD || ''
};
const SECRET = process.env.SESSION_SECRET ||
  crypto.createHash('sha256').update('baby_massage|' + PASS.karina + '|' + PASS.husband).digest('hex');
const SESSION_DAYS = 60;

function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const mac = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return body + '.' + mac;
}
function verify(token) {
  if (!token || token.indexOf('.') < 0) return null;
  const [body, mac] = token.split('.');
  const good = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  const a = Buffer.from(mac), b = Buffer.from(good);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (!p.e || p.e < Date.now()) return null;
    return p;
  } catch (e) { return null; }
}
function parseCookies(req) {
  const out = {};
  String(req.headers.cookie || '').split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  return out;
}
function safeEqual(a, b) {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
}

/* ---------- драйверы хранилища ---------- */
function makeS3Driver(S3Client, cmds) {
  const { GetObjectCommand, PutObjectCommand, ListObjectsV2Command, DeleteObjectCommand } = cmds;
  const client = new S3Client({
    region: process.env.S3_REGION || 'ru-1',
    endpoint: process.env.S3_ENDPOINT,
    forcePathStyle: true,
    credentials: { accessKeyId: process.env.S3_ACCESS_KEY, secretAccessKey: process.env.S3_SECRET_KEY }
  });
  const bucket = process.env.S3_BUCKET;
  const prefix = process.env.S3_PREFIX === undefined ? 'baby_massage/' : process.env.S3_PREFIX;
  const k = name => prefix + name;
  return {
    name: 's3',
    async get(name) {
      try {
        const r = await client.send(new GetObjectCommand({ Bucket: bucket, Key: k(name) }));
        return await r.Body.transformToString();
      } catch (e) {
        if (e && (e.name === 'NoSuchKey' || (e.$metadata && e.$metadata.httpStatusCode === 404))) return null;
        throw e;
      }
    },
    async put(name, body) {
      await client.send(new PutObjectCommand({ Bucket: bucket, Key: k(name), Body: body, ContentType: 'application/json' }));
    },
    async list(pfx) {
      const r = await client.send(new ListObjectsV2Command({ Bucket: bucket, Prefix: k(pfx) }));
      return (r.Contents || []).map(o => o.Key.slice(prefix.length));
    },
    async del(name) {
      await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: k(name) }));
    }
  };
}
function makeFileDriver(dir) {
  fs.mkdirSync(dir, { recursive: true });
  const p = name => path.join(dir, name);
  return {
    name: 'file',
    async get(name) {
      try { return fs.readFileSync(p(name), 'utf8'); }
      catch (e) { if (e.code === 'ENOENT') return null; throw e; }
    },
    async put(name, body) {
      fs.mkdirSync(path.dirname(p(name)), { recursive: true });
      fs.writeFileSync(p(name), body);
    },
    async list(pfx) {
      const base = p(pfx);
      const d = path.dirname(base);
      if (!fs.existsSync(d)) return [];
      const stem = path.basename(base);
      return fs.readdirSync(d).filter(n => n.startsWith(stem)).map(n => path.posix.join(path.posix.dirname(pfx), n));
    },
    async del(name) { try { fs.unlinkSync(p(name)); } catch (e) { /* ignore */ } }
  };
}
function makeDriver() {
  if (process.env.S3_BUCKET) {
    const { S3Client, GetObjectCommand, PutObjectCommand, ListObjectsV2Command, DeleteObjectCommand } = require('@aws-sdk/client-s3');
    return makeS3Driver(S3Client, { GetObjectCommand, PutObjectCommand, ListObjectsV2Command, DeleteObjectCommand });
  }
  console.warn('⚠️  S3_BUCKET не задан — данные пишутся в локальную папку ./data и ПРОПАДУТ при пересборке приложения. Подключите S3!');
  return makeFileDriver(process.env.DATA_DIR || path.join(__dirname, 'data'));
}

/* ---------- состояние ---------- */
function createApp(driver) {
  let state = { version: {}, data: {} };
  let loadOk = false;
  let chain = Promise.resolve();
  const withLock = fn => { const run = chain.then(() => fn()); chain = run.catch(() => {}); return run; };

  async function loadStore() {
    try {
      const body = await driver.get('store.json');
      state = body === null ? { version: {}, data: {} } : JSON.parse(body);
      if (!state.version) state.version = {};
      if (!state.data) state.data = {};
      loadOk = true;
    } catch (e) {
      loadOk = false;
      console.error('Не удалось прочитать store.json:', e && e.message);
    }
    return loadOk;
  }
  const dateKey = (offsetHours) => new Date(Date.now() + (offsetHours || 6) * 3600e3).toISOString().slice(0, 10);

  function arrLen(v) { try { const a = JSON.parse(v); return Array.isArray(a) ? a.length : null; } catch (e) { return null; } }

  async function putValue(key, value, base, force) {
    return withLock(async () => {
      if (!loadOk && !(await loadStore())) { const e = new Error('storage unavailable'); e.status = 503; throw e; }
      const cur = state.version[key] || 0;
      if (cur > 0 && (base === undefined || base === null || Number(base) !== cur)) {
        const e = new Error('conflict'); e.status = 409; e.version = cur; throw e;
      }
      if (cur === 0 && base !== undefined && base !== null && Number(base) !== 0) {
        const e = new Error('conflict'); e.status = 409; e.version = cur; throw e;
      }
      if (ARRAY_GUARD_KEYS.includes(key) && state.data[key] !== undefined) {
        const before = arrLen(state.data[key]), after = arrLen(value);
        if (before !== null && after !== null && before >= 10 && after < before * 0.5) {
          if (!force) { const e = new Error('shrink'); e.status = 409; e.version = cur; e.reason = 'shrink'; throw e; }
          await driver.put('backups/before-restore-' + Date.now() + '.json', JSON.stringify(state));
        }
      }
      const next = {
        version: Object.assign({}, state.version, { [key]: cur + 1 }),
        data: Object.assign({}, state.data, { [key]: value })
      };
      await driver.put('store.json', JSON.stringify(next));
      state = next;
      return cur + 1;
    });
  }

  /* ---------- ежедневная копия ---------- */
  async function sendBackupEmail(key, body) {
    const apiKey = process.env.RESEND_API_KEY, to = process.env.BACKUP_EMAIL;
    if (!apiKey || !to) return false;
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: process.env.BACKUP_FROM || 'onboarding@resend.dev',
        to: [to],
        subject: 'Дневник массажиста — копия данных ' + key,
        text: 'Полная копия данных за ' + key + ' во вложении (JSON).',
        attachments: [{ filename: 'baby_massage-' + key + '.json', content: Buffer.from(body).toString('base64') }]
      })
    });
    if (!r.ok) throw new Error('Resend ' + r.status + ' ' + (await r.text()).slice(0, 200));
    return true;
  }
  async function dailyBackup() {
    try {
      const omskHour = new Date(Date.now() + 6 * 3600e3).getUTCHours();
      if (omskHour < 3) return;
      if (!loadOk) return;
      const key = dateKey(6);
      const body = JSON.stringify(state);
      if ((await driver.get('backups/store-' + key + '.json')) === null) {
        await driver.put('backups/store-' + key + '.json', body);
        const names = (await driver.list('backups/store-')).sort();
        for (const n of names.slice(0, Math.max(0, names.length - 30))) await driver.del(n);
      }
      if (process.env.RESEND_API_KEY && process.env.BACKUP_EMAIL &&
          (await driver.get('backups/emailed-' + key)) === null) {
        if (await sendBackupEmail(key, body)) await driver.put('backups/emailed-' + key, '1');
      }
    } catch (e) { console.error('Ошибка ежедневной копии:', e && e.message); }
  }

  /* ---------- express ---------- */
  const app = express();
  app.set('trust proxy', true);
  app.use(express.json({ limit: '25mb' }));

  const noPasswords = !PASS.karina && !PASS.husband;
  const attempts = new Map();
  function tooMany(ip) {
    const now = Date.now();
    const arr = (attempts.get(ip) || []).filter(t => now - t < 60000);
    attempts.set(ip, arr);
    return arr.length >= 8;
  }

  function currentRole(req) {
    const p = verify(parseCookies(req).bm_session);
    return p && (p.r === 'karina' || p.r === 'husband') ? p.r : null;
  }

  app.get('/health', (req, res) => res.json({ ok: true, storage: driver.name, loaded: loadOk }));

  app.use((req, res, next) => {
    if (noPasswords && req.path !== '/health') {
      return res.status(500).type('html').send('<meta charset="utf-8"><body style="font-family:sans-serif;padding:24px"><h2>Не задан пароль</h2><p>В настройках приложения Timeweb добавьте переменные <b>APP_PASSWORD_KARINA</b> и <b>APP_PASSWORD_HUSBAND</b> (или одну <b>APP_PASSWORD</b>) и перезапустите приложение.</p>');
    }
    next();
  });

  app.get('/login', (req, res) => res.type('html').send(loginPage('')));
  app.post('/api/login', (req, res) => {
    const ip = req.ip || 'x';
    if (tooMany(ip)) return res.status(429).json({ error: 'Слишком много попыток. Подождите минуту.' });
    const pw = String((req.body && req.body.password) || '');
    let role = null;
    if (PASS.karina && safeEqual(pw, PASS.karina)) role = 'karina';
    else if (PASS.husband && safeEqual(pw, PASS.husband)) role = 'husband';
    if (!role) { attempts.get(ip).push(Date.now()); return res.status(401).json({ error: 'Неверный пароль' }); }
    const token = sign({ r: role, e: Date.now() + SESSION_DAYS * 86400e3 });
    const secure = (req.headers['x-forwarded-proto'] || req.protocol) === 'https';
    res.setHeader('Set-Cookie', 'bm_session=' + encodeURIComponent(token) + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + SESSION_DAYS * 86400 + (secure ? '; Secure' : ''));
    res.json({ ok: true, role });
  });
  app.get('/logout', (req, res) => {
    res.setHeader('Set-Cookie', 'bm_session=; Path=/; HttpOnly; Max-Age=0');
    res.redirect('/login');
  });

  app.get('/manifest.webmanifest', (req, res) => res.type('application/manifest+json').json({
    name: 'Дневник массажиста', short_name: 'Массаж', start_url: '/', display: 'standalone',
    background_color: '#F6F1E7', theme_color: '#F6F1E7',
    icons: [{ src: '/icon-192.png', sizes: '192x192', type: 'image/png' }, { src: '/icon-512.png', sizes: '512x512', type: 'image/png' }]
  }));
  ['icon-192.png', 'icon-512.png', 'apple-touch-icon.png'].forEach(f => {
    app.get('/' + f, (req, res) => {
      const fp = path.join(__dirname, 'public', f);
      if (fs.existsSync(fp)) res.sendFile(fp); else res.status(404).end();
    });
  });

  // всё остальное — только после входа
  app.use((req, res, next) => {
    const role = currentRole(req);
    if (role) { req.role = role; return next(); }
    if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'auth' });
    return res.redirect('/login');
  });

  app.get('/api/me', (req, res) => res.json({ role: req.role }));

  app.get('/api/versions', async (req, res) => {
    if (!loadOk && !(await loadStore())) return res.status(503).json({ error: 'storage' });
    res.json({ versions: state.version });
  });

  app.get('/api/storage/:key', async (req, res) => {
    const key = req.params.key;
    if (!KEYS.includes(key)) return res.status(400).json({ error: 'bad key' });
    if (!loadOk && !(await loadStore())) return res.status(503).json({ error: 'storage' });
    const v = state.data[key];
    if (v === undefined) return res.status(404).json({ version: 0 });
    res.json({ value: v, version: state.version[key] || 0 });
  });

  app.put('/api/storage/:key', async (req, res) => {
    const key = req.params.key;
    if (!KEYS.includes(key)) return res.status(400).json({ error: 'bad key' });
    const value = req.body && req.body.value;
    if (typeof value !== 'string') return res.status(400).json({ error: 'value must be a string' });
    try { JSON.parse(value); } catch (e) { return res.status(400).json({ error: 'value must be JSON' }); }
    try {
      const version = await putValue(key, value, req.body.base, req.get('x-force') === '1');
      res.json({ ok: true, version });
    } catch (e) {
      if (e.status === 409) return res.status(409).json({ error: 'conflict', reason: e.reason || 'version', version: e.version });
      console.error('Ошибка записи:', e && e.message);
      res.status(e.status || 500).json({ error: 'storage' });
    }
  });

  // полная копия для руководителя (Карины)
  app.get('/api/raw-backup', async (req, res) => {
    if (req.role !== 'karina') return res.status(403).json({ error: 'forbidden' });
    if (!loadOk && !(await loadStore())) return res.status(503).json({ error: 'storage' });
    res.setHeader('Content-Disposition', 'attachment; filename="baby_massage-' + dateKey(6) + '.json"');
    res.type('application/json').send(JSON.stringify(state, null, 2));
  });

  app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html', maxAge: 0 }));

  return { app, loadStore, dailyBackup, _internals: { getState: () => state, withLock, putValue } };
}

function loginPage(msg) {
  return `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Вход · Дневник массажиста</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#F6F1E7;font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#1F2A24}
.box{width:100%;max-width:340px;padding:28px 22px;background:#FBF8F2;border:1px solid #E6DCC8;border-radius:18px;margin:16px}
h1{font-family:Georgia,serif;font-size:22px;margin:0 0 4px}p{margin:0 0 18px;color:#6B6F66;font-size:14px}
input{width:100%;box-sizing:border-box;padding:13px;border:1px solid #D9CFB8;border-radius:12px;font-size:16px;margin-bottom:12px;background:#fff}
button{width:100%;padding:13px;border:none;border-radius:12px;background:#1F3A2E;color:#fff;font-size:16px;font-weight:600;cursor:pointer}
#err{color:#B03A2A;font-size:13.5px;min-height:18px;margin-bottom:8px}
</style></head><body><div class="box"><h1>Дневник массажиста</h1><p>Введите пароль</p>
<input id="pw" type="password" autocomplete="current-password" placeholder="Пароль" autofocus>
<div id="err">${msg}</div><button id="go" type="button">Войти</button></div>
<script>
async function go(){var e=document.getElementById('err');e.textContent='';
try{var r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('pw').value})});
var j=await r.json();if(r.ok){location.href='/';}else{e.textContent=j.error||'Ошибка входа';}}catch(x){e.textContent='Нет связи с сервером';}}
document.getElementById('go').addEventListener('click',go);
document.getElementById('pw').addEventListener('keydown',function(ev){if(ev.key==='Enter')go();});
</script></body></html>`;
}

module.exports = { createApp, makeFileDriver, makeS3Driver, makeDriver };

if (require.main === module) {
  const driver = makeDriver();
  const { app, loadStore, dailyBackup } = createApp(driver);
  loadStore().then(() => {
    app.listen(PORT, () => console.log('baby_massage запущен на порту ' + PORT + ', хранилище: ' + driver.name));
    setInterval(dailyBackup, 30 * 60 * 1000);
    setTimeout(dailyBackup, 20000);
  });
}
