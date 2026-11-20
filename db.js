// Sakura Chat 🌸 — capa de base de datos
// - Si existe DATABASE_URL → Postgres (Render gratis + Neon)
// - Si no → SQLite local integrado de Node (sin dependencias nativas)
// La API es la misma en ambos: db.prepare(sql).get/.all/.run (async)
// Patrón copiado de Contigo (~/workspace/contigo/db.js).
// En Render, Postgres es OBLIGATORIO: el disco del plan gratis es efímero,
// así que SQLite en Render NO es persistente.
const path = require('path');
const fs = require('fs');

const usePg = !!process.env.DATABASE_URL;

const SQLITE_SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  email TEXT,
  password_hash TEXT NOT NULL,
  display_name TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS chats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL,
  name TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS chat_members (
  chat_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  joined_at TEXT NOT NULL,
  PRIMARY KEY (chat_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_chat_members_user ON chat_members (user_id);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  chat_id INTEGER NOT NULL,
  sender_id INTEGER NOT NULL,
  sender_display_name TEXT NOT NULL,
  kind TEXT NOT NULL,
  body_enc TEXT NOT NULL,
  iv TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages (chat_id, id);
CREATE TABLE IF NOT EXISTS message_reads (
  message_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  read_at TEXT NOT NULL,
  PRIMARY KEY (message_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_reads_message ON message_reads (message_id);
`;

const PG_SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  email TEXT,
  password_hash TEXT NOT NULL,
  display_name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS chats (
  id SERIAL PRIMARY KEY,
  type TEXT NOT NULL,
  name TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS chat_members (
  chat_id INT NOT NULL,
  user_id INT NOT NULL,
  joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (chat_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_chat_members_user ON chat_members (user_id);
CREATE TABLE IF NOT EXISTS messages (
  id SERIAL PRIMARY KEY,
  chat_id INT NOT NULL,
  sender_id INT NOT NULL,
  sender_display_name TEXT NOT NULL,
  kind TEXT NOT NULL,
  body_enc TEXT NOT NULL,
  iv TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages (chat_id, id);
CREATE TABLE IF NOT EXISTS message_reads (
  message_id INT NOT NULL,
  user_id INT NOT NULL,
  read_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (message_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_reads_message ON message_reads (message_id);
`;

let db;
const ready = (async () => {
  if (usePg) {
    let pool;
    try {
      const { Pool } = require('pg');
      pool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false }, // Neon exige TLS
        max: 5,
      });
      await pool.query(PG_SCHEMA);
      // Migración v3 (login con correo): añade email si la tabla ya existía
      // sin esa columna. Índice único parcial: varios NULL permitidos,
      // pero un mismo correo (en minúsculas) solo una vez.
      await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT');
      await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users (LOWER(email)) WHERE email IS NOT NULL');
    } catch (e) {
      console.error('Sakura Chat ERROR: DATABASE_URL está configurada pero no se pudo conectar a Postgres.');
      console.error('Sakura Chat Revisa en Render → Environment que la KEY sea exactamente DATABASE_URL y que el VALUE sea el postgresql://... completo de Neon, sin espacios ni saltos de línea. Detalle:', e.message);
      throw e;
    }
    const toPg = (sql) => {
      let i = 0;
      return sql.replace(/\?/g, () => '$' + (++i));
    };
    // chat_members y message_reads no tienen columna id → no pedir RETURNING id
    const NO_ID_TABLES = new Set(['chat_members', 'message_reads']);
    db = {
      kind: 'pg',
      prepare: (sql) => {
        const m = /^\s*insert\s+into\s+"?(\w+)/i.exec(sql);
        const wantId = m && !NO_ID_TABLES.has(m[1].toLowerCase());
        const pgSql = toPg(sql) + (wantId ? ' RETURNING id' : '');
        const base = toPg(sql);
        return {
          get: async (...p) => (await pool.query(base, p)).rows[0],
          all: async (...p) => (await pool.query(base, p)).rows,
          run: async (...p) => {
            const r = await pool.query(pgSql, p);
            return { lastInsertRowid: r.rows[0] ? r.rows[0].id : undefined, changes: r.rowCount };
          },
        };
      },
    };
    console.log('Sakura Chat usando Postgres');
  } else {
    const { DatabaseSync } = require('node:sqlite');
    const dbPath = process.env.DB_PATH || path.join(__dirname, 'data', 'sakura.db');
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    const raw = new DatabaseSync(dbPath);
    raw.exec('PRAGMA journal_mode = WAL');
    raw.exec(SQLITE_SCHEMA);
    // Migración v3 (login con correo): bases locales creadas por v1/v2 no
    // tienen la columna email. ADD COLUMN falla si ya existe: se ignora.
    try { raw.exec('ALTER TABLE users ADD COLUMN email TEXT'); } catch { /* ya existe */ }
    raw.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users (LOWER(email)) WHERE email IS NOT NULL');
    db = {
      kind: 'sqlite',
      prepare: (sql) => {
        const st = raw.prepare(sql);
        return {
          get: async (...p) => st.get(...p),
          all: async (...p) => st.all(...p),
          run: async (...p) => st.run(...p),
        };
      },
    };
    console.log('Sakura Chat usando SQLite local');
  }
})();

module.exports = {
  ready,
  kind: usePg ? 'postgres' : 'sqlite',
  prepare: (sql) => {
    if (!db) throw new Error('DB no inicializada');
    return db.prepare(sql);
  },
};
