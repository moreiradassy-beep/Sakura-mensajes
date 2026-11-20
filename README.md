# Sakura Chat 🌸 — Servidor

App privada de mensajes solo por internet (sin SMS/RCS) para la familia.
Backend: Node.js + Express 4 + Postgres (Neon) / SQLite local + Socket.IO + JWT.

## Estructura

```
server/
├── server.js      # API REST + Socket.IO
├── db.js          # Postgres (DATABASE_URL) o SQLite local, misma API
├── crypto.js      # AES-256-GCM en reposo
├── package.json
├── render.yaml    # Blueprint de Render (servicio sakura-chat-familia)
├── DEPLOY.md      # pasos exactos para publicar en Render
├── .env.example   # variables locales (copiar a .env, nunca subir)
└── data/          # SQLite local (solo desarrollo, no se sube)
```

## Desarrollo local

```bash
npm install
cp .env.example .env   # rellena JWT_SECRET y ENCRYPTION_KEY (64 hex chars)
node server.js         # http://localhost:3000, SQLite en data/sakura.db
```

Sin `DATABASE_URL` usa SQLite local. Con `DATABASE_URL` usa Postgres
(Neon) y crea las tablas solas al arrancar.

## Variables de entorno

| Variable | Obligatoria | Notas |
|---|---|---|
| `JWT_SECRET` | sí (prod.) | Secreto para firmar los JWT (90 días). |
| `ENCRYPTION_KEY` | sí (prod.) | Clave de cifrado en reposo. Acepta 32 bytes en hex (64 caracteres) o cualquier texto (se deriva con SHA-256). El `generateValue` de Render sirve tal cual. **Si cambia, los mensajes viejos ya no se podrán descifrar: no rotarla sin migrar.** |
| `DATABASE_URL` | sí (Render) | Connection string de Neon, base de datos `sakurachat`. |
| `PORT` | no | Render la pone sola; local por defecto 3000. |
| `DB_PATH` | no | Ruta del SQLite local. |

## API (contrato)

JSON en todo. Auth: `Authorization: Bearer <token>`. Errores en español
(`{error: "..."}`).

- `GET /api/health` → `{ok:true}`
- `POST /api/auth/register` `{name, email, password}` → `{token, user}`
  (v4: un solo nombre; el usuario interno se deriva del nombre en
  minúsculas, sin acentos ni espacios, 3–20 chars `[a-z0-9_]`; correo
  obligatorio y válido, correo único, clave mín. 6, hash bcrypt).
  También acepta el formato viejo `{username, displayName, ...}`.
  El correo nunca se expone en búsquedas ni en el perfil público.
- `POST /api/auth/login` `{username, password}` → `{token, user}` — el
  campo `username` acepta usuario **o** correo (si tiene @, busca por
  email; si no, por username), sin distinguir mayúsculas.
- `GET /api/users/search?q=` → `[{id, username, displayName}]` (sin uno mismo)
- `GET /api/chats` → `[{id, type, name, members, lastMessage, updatedAt, unreadCount}]`
- `POST /api/chats` `{type:"dm"|"group", memberIds, name?}` → chat (el DM
  existente entre los mismos dos usuarios se reutiliza, no se duplica)
- `GET /api/chats/:id/messages?limit=50&before=<id>` → mensajes en orden
  antiguo → reciente. Extra: `?since=<ISO>` para sondear mensajes nuevos.
- `POST /api/chats/:id/messages` `{kind:"text", text}` → mensaje creado
- `POST /api/chats/:id/messages/image` `{imageData:"data:image/...;base64,..."}`
  → mensaje creado. Más de 2 MB → 413.
- `POST /api/chats/:id/read` `{lastMessageId}` → `{ok:true}`
- `POST /api/chats/:id/typing` `{typing}` → `{ok:true}` (solo difunde)
- `GET /api/chats/:id/typing` → `{typing:[{userId, displayName}]}` (extra
  para la app Android; el contrato principal solo define el POST)

### Socket.IO

Auth en el handshake (`auth: {token}`). El cliente emite `join {chatId}`.
El servidor emite a la sala `chat:<id>`:

- `message:new` (objeto de mensaje completo)
- `typing` `{chatId, userId, displayName, typing}`
- `message:read` `{chatId, messageId, userId}`

Al conectar, el servidor une el socket a todos los chats del usuario.

## Protección (límites honestos)

- **Transporte:** TLS (HTTPS en Render).
- **En reposo:** AES-256-GCM con IV aleatorio por mensaje; en la base de
  datos solo se guardan `iv` + texto cifrado (base64). Nunca se guarda el
  texto plano ni se registra el contenido de los mensajes en los logs.
- **NO es cifrado de extremo a extremo:** la clave la guarda el servidor,
  así que el servidor puede descifrar los mensajes. Es cifrado en reposo
  con clave del servidor, no E2EE.
- Sin anuncios ni rastreadores.
