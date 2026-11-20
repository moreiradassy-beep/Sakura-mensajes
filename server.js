// Sakura Chat 🌸 — backend: Express + Postgres/SQLite + Socket.IO + JWT
// App privada de mensajes solo por internet (sin SMS/RCS) para la familia.
// - Auth: JWT (Bearer) + bcryptjs
// - Mensajes cifrados en reposo (AES-256-GCM, ver crypto.js)
// - Sin anuncios, sin rastreadores. Los logs NUNCA incluyen el contenido
//   de los mensajes, solo metadatos de errores.
//
// LÍMITE HONESTO: el cifrado es en reposo con clave del servidor + TLS en
// transporte. NO es cifrado de extremo a extremo: el servidor puede
// descifrar los mensajes.
const fs = require('fs');
const path = require('path');

// Carga .env local (desarrollo) sin dependencias extra. En Render las
// variables vienen del entorno; .env nunca se sube al repo (.gitignore).
(function loadDotEnv() {
  try {
    const envPath = path.join(__dirname, '.env');
    if (!fs.existsSync(envPath)) return;
    for (const line of fs.readFileSync(envPath, 'utf8').split('\n')) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
      if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
    }
  } catch (e) { /* .env opcional */ }
})();

const express = require('express');
const http = require('http');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { Server } = require('socket.io');
const db = require('./db');
const { encrypt, decrypt } = require('./crypto');

const JWT_SECRET = process.env.JWT_SECRET || 'sakura-dev-secret-cambiar-en-produccion';
const PORT = process.env.PORT || 3000;
const MAX_IMAGE_BYTES = 2 * 1024 * 1024; // 2 MB (data URI completa)
const MAX_TEXT_LEN = 2000;

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json({ limit: '3mb' }));

// ---------- web para iPhone / Safari ----------
// La versión web vive en el mismo servidor (sin servicio nuevo ni costo):
// GET / sirve public/index.html (misma API, mismos chats y cuentas que la
// app Android). express.static solo sirve archivos que existen en public/;
// las rutas /api/* no son archivos, así que siguen llegando a la API.
// Iconos para "Anadir a pantalla de inicio" en iPhone. El push a GitHub
// por snapshot solo admite archivos UTF-8 (sin binarios), asi que los PNG
// van incrustados en base64 y se sirven por ruta; public/ no los contiene.
const ICON_180_B64 = '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';
const ICON_512_B64 = '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';
app.get('/icon-180.png', (req, res) => {
  res.type('png').send(Buffer.from(ICON_180_B64, 'base64'));
});
app.get('/icon-512.png', (req, res) => {
  res.type('png').send(Buffer.from(ICON_512_B64, 'base64'));
});
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ---------- helpers ----------
function signToken(userId) {
  return jwt.sign({ uid: userId }, JWT_SECRET, { expiresIn: '90d' });
}
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No autorizado' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.uid;
    next();
  } catch {
    return res.status(401).json({ error: 'Sesión inválida' });
  }
}
const asyncH = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// Normaliza fechas (Postgres devuelve Date, SQLite texto) a ISO string.
function iso(v) {
  if (v === null || v === undefined) return null;
  if (v instanceof Date) return v.toISOString();
  if (typeof v === 'number') return new Date(v).toISOString();
  return String(v);
}
function nowIso() { return new Date().toISOString(); }

async function getUser(id) {
  return db.prepare('SELECT id, username, display_name FROM users WHERE id = ?').get(id);
}
function publicUser(u) {
  return u ? { id: u.id, username: u.username, displayName: u.display_name } : null;
}
async function getMembers(chatId) {
  const rows = await db.prepare(
    'SELECT u.id, u.username, u.display_name FROM chat_members cm JOIN users u ON u.id = cm.user_id WHERE cm.chat_id = ? ORDER BY u.display_name'
  ).all(chatId);
  return rows.map((r) => ({ id: r.id, username: r.username, displayName: r.display_name }));
}
async function isMember(chatId, userId) {
  const row = await db.prepare('SELECT 1 AS ok FROM chat_members WHERE chat_id = ? AND user_id = ?').get(chatId, userId);
  return !!row;
}
async function getChatRow(chatId) {
  return db.prepare('SELECT id, type, name, created_at FROM chats WHERE id = ?').get(chatId);
}

// Construye el objeto chat del contrato, con último mensaje y no leídos.
async function buildChat(chatRow, myId) {
  const members = await getMembers(chatRow.id);
  const lastRow = await db.prepare(
    'SELECT id, sender_id, sender_display_name, kind, body_enc, iv, created_at FROM messages WHERE chat_id = ? ORDER BY id DESC LIMIT 1'
  ).get(chatRow.id);
  let lastMessage = null;
  let updatedAt = iso(chatRow.created_at);
  if (lastRow) {
    updatedAt = iso(lastRow.created_at);
    let text = '';
    if (lastRow.kind === 'image') {
      text = '📷 Foto';
    } else {
      try { text = decrypt(lastRow.iv, lastRow.body_enc); } catch { text = ''; }
    }
    lastMessage = {
      text,
      kind: lastRow.kind,
      createdAt: iso(lastRow.created_at),
      senderDisplayName: lastRow.sender_display_name,
    };
  }
  const unread = await db.prepare(
    `SELECT COUNT(*) AS c FROM messages m WHERE m.chat_id = ? AND m.sender_id <> ?
     AND NOT EXISTS (SELECT 1 FROM message_reads r WHERE r.message_id = m.id AND r.user_id = ?)`
  ).get(chatRow.id, myId, myId);
  return {
    id: chatRow.id,
    type: chatRow.type,
    name: chatRow.name || null,
    members,
    lastMessage,
    updatedAt,
    unreadCount: Number(unread ? unread.c : 0),
  };
}

// Convierte una fila de messages en el objeto del contrato (descifra).
async function buildMessage(row, readByMap) {
  let text = '';
  let imageData = null;
  try {
    const plain = decrypt(row.iv, row.body_enc);
    if (row.kind === 'image') imageData = plain;
    else text = plain;
  } catch {
    // Si no se puede descifrar (clave distinta), no se expone nada.
    text = '';
  }
  return {
    id: row.id,
    chatId: row.chat_id,
    senderId: row.sender_id,
    senderDisplayName: row.sender_display_name,
    kind: row.kind,
    text,
    imageData,
    createdAt: iso(row.created_at),
    readBy: readByMap ? (readByMap[row.id] || []) : [],
  };
}

async function loadReadBy(messageIds) {
  const map = {};
  if (!messageIds.length) return map;
  const ph = messageIds.map(() => '?').join(',');
  const rows = await db.prepare(
    `SELECT message_id, user_id FROM message_reads WHERE message_id IN (${ph})`
  ).all(...messageIds);
  for (const r of rows) (map[r.message_id] = map[r.message_id] || []).push(r.user_id);
  return map;
}

async function insertMessage(chatId, senderId, senderDisplayName, kind, plaintext) {
  const { iv, data } = encrypt(plaintext);
  const r = await db.prepare(
    'INSERT INTO messages (chat_id, sender_id, sender_display_name, kind, body_enc, iv, created_at) VALUES (?,?,?,?,?,?,?)'
  ).run(chatId, senderId, senderDisplayName, kind, data, iv, nowIso());
  const row = await db.prepare('SELECT * FROM messages WHERE id = ?').get(r.lastInsertRowid);
  // El remitente ya "leyó" su propio mensaje.
  await db.prepare('INSERT INTO message_reads (message_id, user_id, read_at) VALUES (?,?,?) ON CONFLICT DO NOTHING')
    .run(row.id, senderId, nowIso());
  const msg = await buildMessage(row, { [row.id]: [senderId] });
  io.to('chat:' + chatId).emit('message:new', msg);
  return msg;
}

// ---------- estado de "escribiendo" (solo memoria, expira en segundos) ----------
const typingState = new Map(); // chatId -> Map(userId -> {displayName, at})
function setTyping(chatId, userId, displayName, typing) {
  let m = typingState.get(chatId);
  if (!m) { m = new Map(); typingState.set(chatId, m); }
  if (typing) m.set(userId, { displayName, at: Date.now() });
  else m.delete(userId);
}
function getTyping(chatId) {
  const m = typingState.get(chatId);
  if (!m) return [];
  const now = Date.now();
  const out = [];
  for (const [userId, v] of m) {
    if (now - v.at > 6000) { m.delete(userId); continue; }
    out.push({ userId, displayName: v.displayName });
  }
  return out;
}

// ---------- salud ----------
app.get('/api/health', (req, res) => res.json({ ok: true }));

// ---------- auth ----------
const USERNAME_RE = /^[a-z0-9_]{3,20}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
// v4: un solo nombre. El usuario interno se deriva del nombre: minúsculas,
// sin acentos, espacios y signos -> "_", máx. 20. Ej.: "Jasmin Moreira" ->
// "jasmin_moreira"; "María José" -> "maria_jose". Idéntico al de la app.
function normalizeUsername(name) {
  let s = String(name || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  s = s.toLowerCase().trim().replace(/[^a-z0-9]+/g, '_').replace(/_+/g, '_').replace(/^_+|_+$/g, '');
  return s.slice(0, 20).replace(/_+$/, '');
}
app.post('/api/auth/register', asyncH(async (req, res) => {
  const { username, password, displayName, email, name } = req.body || {};
  // Un solo nombre: displayName = nombre tal cual; si un cliente viejo
  // manda usuario y nombre por separado, el usuario explícito y válido
  // manda; si no, se deriva del nombre. Las cuentas viejas no cambian.
  const display = String(displayName || name || username || '').trim().slice(0, 40);
  const rawU = String(username || '').trim().toLowerCase();
  const uname = USERNAME_RE.test(rawU) ? rawU : normalizeUsername(display);
  const mail = String(email || '').trim().toLowerCase();
  if (!USERNAME_RE.test(uname))
    return res.status(400).json({ error: 'Escribe un nombre de al menos 3 letras, solo letras y números' });
  if (!EMAIL_RE.test(mail))
    return res.status(400).json({ error: 'Escribe un correo válido, por ejemplo nombre@correo.com' });
  if (!display)
    return res.status(400).json({ error: 'Escribe tu nombre (máximo 40 caracteres)' });
  if (typeof password !== 'string' || password.length < 6)
    return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
  const exists = await db.prepare('SELECT id FROM users WHERE username = ?').get(uname);
  if (exists) return res.status(400).json({ error: 'Ese nombre ya está en uso, prueba con otro nombre' });
  const emailExists = await db.prepare('SELECT id FROM users WHERE LOWER(email) = ?').get(mail);
  if (emailExists) return res.status(400).json({ error: 'Ese correo ya está en uso' });
  const hash = bcrypt.hashSync(password, 10);
  const r = await db.prepare('INSERT INTO users (username, email, password_hash, display_name, created_at) VALUES (?,?,?,?,?)')
    .run(uname, mail, hash, display, nowIso());
  const user = await getUser(r.lastInsertRowid);
  res.json({ token: signToken(user.id), user: publicUser(user) });
}));

app.post('/api/auth/login', asyncH(async (req, res) => {
  // Acepta usuario O correo: si el identificador tiene @, se busca por
  // email; si no, por username. Sin distinguir mayúsculas/minúsculas.
  const identifier = String(req.body?.username || req.body?.identifier || req.body?.email || '').trim().toLowerCase();
  const { password } = req.body || {};
  let u = null;
  if (identifier.includes('@')) {
    u = await db.prepare('SELECT * FROM users WHERE LOWER(email) = ?').get(identifier);
  } else {
    u = await db.prepare('SELECT * FROM users WHERE username = ?').get(identifier);
  }
  if (!u || !bcrypt.compareSync(String(password || ''), u.password_hash))
    return res.status(400).json({ error: 'Usuario o correo, o contraseña, incorrectos' });
  res.json({ token: signToken(u.id), user: publicUser(u) });
}));

// ---------- usuarios ----------
app.get('/api/users/search', auth, asyncH(async (req, res) => {
  const q = String(req.query.q || '').trim().toLowerCase();
  if (!q) return res.json([]);
  const like = '%' + q.replace(/([%_\\])/g, '\\$1') + '%';
  const rows = await db.prepare(
    "SELECT id, username, display_name FROM users WHERE id <> ? AND (LOWER(username) LIKE ? ESCAPE '\\' OR LOWER(display_name) LIKE ? ESCAPE '\\') ORDER BY display_name LIMIT 20"
  ).all(req.userId, like, like);
  res.json(rows.map(publicUser));
}));

// ---------- chats ----------
app.get('/api/chats', auth, asyncH(async (req, res) => {
  const rows = await db.prepare(
    `SELECT c.id, c.type, c.name, c.created_at,
            COALESCE(MAX(m.created_at), c.created_at) AS updated_at
     FROM chats c
     LEFT JOIN messages m ON m.chat_id = c.id
     WHERE c.id IN (SELECT chat_id FROM chat_members WHERE user_id = ?)
     GROUP BY c.id, c.type, c.name, c.created_at
     ORDER BY updated_at DESC`
  ).all(req.userId);
  const out = [];
  for (const r of rows) out.push(await buildChat(r, req.userId));
  res.json(out);
}));

app.post('/api/chats', auth, asyncH(async (req, res) => {
  const { type, memberIds, name } = req.body || {};
  if (type !== 'dm' && type !== 'group')
    return res.status(400).json({ error: 'El tipo de chat debe ser "dm" o "group"' });
  if (!Array.isArray(memberIds) || memberIds.length === 0)
    return res.status(400).json({ error: 'Faltan los participantes del chat' });
  const ids = [...new Set(memberIds.map((v) => Number(v)).filter((v) => Number.isInteger(v) && v > 0))];
  if (!ids.includes(req.userId)) ids.push(req.userId);
  // Todos los participantes deben existir.
  const ph = ids.map(() => '?').join(',');
  const found = await db.prepare(`SELECT id FROM users WHERE id IN (${ph})`).all(...ids);
  if (found.length !== ids.length)
    return res.status(400).json({ error: 'Uno de los participantes no existe' });

  if (type === 'dm') {
    if (ids.length !== 2)
      return res.status(400).json({ error: 'Un chat directo es entre dos personas' });
    const [a, b] = ids;
    const existing = await db.prepare(
      `SELECT c.id FROM chats c WHERE c.type = 'dm'
       AND EXISTS (SELECT 1 FROM chat_members WHERE chat_id = c.id AND user_id = ?)
       AND EXISTS (SELECT 1 FROM chat_members WHERE chat_id = c.id AND user_id = ?)
       AND (SELECT COUNT(*) FROM chat_members WHERE chat_id = c.id) = 2`
    ).get(a, b);
    if (existing) {
      const row = await getChatRow(existing.id);
      return res.json(await buildChat(row, req.userId));
    }
  } else {
    if (ids.length < 3)
      return res.status(400).json({ error: 'Un grupo necesita al menos 3 personas' });
    if (!name || !String(name).trim())
      return res.status(400).json({ error: 'El grupo necesita un nombre' });
  }

  const chatName = type === 'group' ? String(name).trim().slice(0, 60) : null;
  const r = await db.prepare('INSERT INTO chats (type, name, created_at) VALUES (?,?,?)')
    .run(type, chatName, nowIso());
  const chatId = r.lastInsertRowid;
  for (const uid of ids) {
    await db.prepare('INSERT INTO chat_members (chat_id, user_id, joined_at) VALUES (?,?,?) ON CONFLICT DO NOTHING')
      .run(chatId, uid, nowIso());
  }
  const row = await getChatRow(chatId);
  res.json(await buildChat(row, req.userId));
}));

// ---------- mensajes ----------
app.get('/api/chats/:id/messages', auth, asyncH(async (req, res) => {
  const chatId = Number(req.params.id);
  if (!Number.isInteger(chatId)) return res.status(404).json({ error: 'Chat no encontrado' });
  if (!(await isMember(chatId, req.userId))) return res.status(404).json({ error: 'Chat no encontrado' });
  let limit = parseInt(req.query.limit || '50', 10);
  if (!Number.isFinite(limit) || limit < 1) limit = 50;
  if (limit > 100) limit = 100;
  const before = req.query.before ? Number(req.query.before) : null;
  const since = req.query.since ? String(req.query.since) : null;
  let rows;
  if (before !== null && Number.isInteger(before)) {
    // Los `limit` más recientes antes de ese id, en orden antiguo → reciente.
    const recent = await db.prepare(
      'SELECT * FROM messages WHERE chat_id = ? AND id < ? ORDER BY id DESC LIMIT ?'
    ).all(chatId, before, limit);
    rows = recent.reverse();
  } else if (since) {
    rows = await db.prepare(
      'SELECT * FROM messages WHERE chat_id = ? AND created_at > ? ORDER BY id ASC LIMIT ?'
    ).all(chatId, since, limit);
  } else {
    const recent = await db.prepare(
      'SELECT * FROM messages WHERE chat_id = ? ORDER BY id DESC LIMIT ?'
    ).all(chatId, limit);
    rows = recent.reverse();
  }
  const readBy = await loadReadBy(rows.map((r) => r.id));
  const out = [];
  for (const r of rows) out.push(await buildMessage(r, readBy));
  res.json(out);
}));

app.post('/api/chats/:id/messages', auth, asyncH(async (req, res) => {
  const chatId = Number(req.params.id);
  if (!Number.isInteger(chatId)) return res.status(404).json({ error: 'Chat no encontrado' });
  if (!(await isMember(chatId, req.userId))) return res.status(404).json({ error: 'Chat no encontrado' });
  const { kind, text } = req.body || {};
  if (kind !== undefined && kind !== 'text')
    return res.status(400).json({ error: 'Para imágenes usa el endpoint de imágenes' });
  const msg = String(text || '').trim();
  if (!msg) return res.status(400).json({ error: 'El mensaje está vacío' });
  if (msg.length > MAX_TEXT_LEN)
    return res.status(400).json({ error: `El mensaje no puede tener más de ${MAX_TEXT_LEN} caracteres` });
  const me = await getUser(req.userId);
  res.json(await insertMessage(chatId, req.userId, me.display_name, 'text', msg));
}));

app.post('/api/chats/:id/messages/image', auth, asyncH(async (req, res) => {
  const chatId = Number(req.params.id);
  if (!Number.isInteger(chatId)) return res.status(404).json({ error: 'Chat no encontrado' });
  if (!(await isMember(chatId, req.userId))) return res.status(404).json({ error: 'Chat no encontrado' });
  const { imageData } = req.body || {};
  if (typeof imageData !== 'string' || !imageData)
    return res.status(400).json({ error: 'Falta la imagen' });
  if (imageData.length > MAX_IMAGE_BYTES)
    return res.status(413).json({ error: 'La imagen es demasiado grande (máximo 2 MB)' });
  if (!/^data:image\/[a-zA-Z0-9.+-]+;base64,/.test(imageData))
    return res.status(400).json({ error: 'La imagen debe ser un data URI base64 (data:image/...)' });
  const me = await getUser(req.userId);
  res.json(await insertMessage(chatId, req.userId, me.display_name, 'image', imageData));
}));

// ---------- leído ----------
app.post('/api/chats/:id/read', auth, asyncH(async (req, res) => {
  const chatId = Number(req.params.id);
  if (!Number.isInteger(chatId)) return res.status(404).json({ error: 'Chat no encontrado' });
  if (!(await isMember(chatId, req.userId))) return res.status(404).json({ error: 'Chat no encontrado' });
  const lastMessageId = Number(req.body?.lastMessageId);
  if (!Number.isInteger(lastMessageId))
    return res.status(400).json({ error: 'Falta el último mensaje leído' });
  const rows = await db.prepare(
    'SELECT id FROM messages WHERE chat_id = ? AND id <= ? AND sender_id <> ?'
  ).all(chatId, lastMessageId, req.userId);
  const at = nowIso();
  for (const r of rows) {
    await db.prepare('INSERT INTO message_reads (message_id, user_id, read_at) VALUES (?,?,?) ON CONFLICT DO NOTHING')
      .run(r.id, req.userId, at);
  }
  io.to('chat:' + chatId).emit('message:read', { chatId, messageId: lastMessageId, userId: req.userId });
  res.json({ ok: true });
}));

// ---------- escribiendo ----------
app.post('/api/chats/:id/typing', auth, asyncH(async (req, res) => {
  const chatId = Number(req.params.id);
  if (!Number.isInteger(chatId)) return res.status(404).json({ error: 'Chat no encontrado' });
  if (!(await isMember(chatId, req.userId))) return res.status(404).json({ error: 'Chat no encontrado' });
  const typing = req.body?.typing !== false;
  const me = await getUser(req.userId);
  setTyping(chatId, req.userId, me.display_name, typing);
  io.to('chat:' + chatId).emit('typing', { chatId, userId: req.userId, displayName: me.display_name, typing });
  res.json({ ok: true });
}));

// Extra (lo usa la app Android para sondear quién escribe; el contrato
// principal solo define el POST). Devuelve { typing: [{userId, displayName}] }.
app.get('/api/chats/:id/typing', auth, asyncH(async (req, res) => {
  const chatId = Number(req.params.id);
  if (!Number.isInteger(chatId)) return res.status(404).json({ error: 'Chat no encontrado' });
  if (!(await isMember(chatId, req.userId))) return res.status(404).json({ error: 'Chat no encontrado' });
  res.json({ typing: getTyping(chatId).filter((t) => t.userId !== req.userId) });
}));

// ---------- socket.io ----------
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error('no token'));
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    socket.userId = payload.uid;
    next();
  } catch { next(new Error('bad token')); }
});

io.on('connection', (socket) => {
  (async () => {
    const me = await getUser(socket.userId);
    socket.displayName = me ? me.display_name : '';
    const rows = await db.prepare('SELECT chat_id FROM chat_members WHERE user_id = ?').all(socket.userId);
    for (const r of rows) socket.join('chat:' + r.chat_id);
  })();

  socket.on('join', async ({ chatId } = {}) => {
    const id = Number(chatId);
    if (!Number.isInteger(id)) return;
    if (await isMember(id, socket.userId)) socket.join('chat:' + id);
  });

  socket.on('typing', async ({ chatId, typing } = {}) => {
    const id = Number(chatId);
    if (!Number.isInteger(id)) return;
    if (!(await isMember(id, socket.userId))) return;
    const on = typing !== false;
    setTyping(id, socket.userId, socket.displayName || '', on);
    io.to('chat:' + id).emit('typing', { chatId: id, userId: socket.userId, displayName: socket.displayName || '', typing: on });
  });
});

// ---------- errores ----------
app.use((err, req, res, _next) => {
  // Solo metadatos del error en el log, nunca contenido de mensajes.
  console.error('API error:', req.method, req.path, err.status || '', err.message);
  if (err.type === 'entity.too.large')
    return res.status(413).json({ error: 'El contenido es demasiado grande (máximo 2 MB por imagen)' });
  res.status(500).json({ error: 'Algo salió mal 💔' });
});

(async () => {
  await db.ready;
  server.listen(PORT, () => console.log(`Sakura Chat 🌸 escuchando en http://localhost:${PORT} (db: ${db.kind})`));
})();
