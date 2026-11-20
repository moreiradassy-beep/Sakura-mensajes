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
