# DEPLOY.md — Publicar Sakura Chat en Render (gratis)

El servidor ya está probado en local. Falta publicarlo: **no se pudo
desplegar desde esta máquina** (ver "Bloqueador" abajo). Pasos exactos:

> **Nombre nuevo (v3):** `sakura-chat.onrender.com` ya lo ocupa otra app
> (una app rusa llamada «Сакура», sin `/api/health` ni
> `/api/auth/register` — por eso la app mostraba «Cannot POST
> /api/auth/register»). El servicio nuestro se llama
> **`sakura-chat-familia`** → `https://sakura-chat-familia.onrender.com`.
> Ese nombre se comprobó libre con curl el 2026-11-20: Render responde
> «Not Found» (no existe ningún servicio), mientras el nombre viejo
> responde con la página de la app rusa.

## 0. Bloqueador (por qué no está ya en línea)

- No hay CLI de Render en esta máquina (`which render` → nada).
- `gh` no tiene sesión iniciada (`gh auth status` → "not logged into any
  GitHub hosts"), así que no se pudo crear el repositorio de GitHub que
  Render necesita.
- Render no tiene credencial guardada aquí (ni API key ni sesión de
  dashboard accesible desde la terminal).

Lo que falta es un paso con la cuenta de Dassy/Edwin: iniciar sesión en
GitHub y en Render (dashboard) y seguir los pasos 1–3. Son ~10 minutos.

## 1. Subir el código a GitHub

El repositorio debe tener como raíz el contenido de `server/` (o sea,
`server.js`, `package.json` y `render.yaml` en la raíz del repo).

```bash
cd ~/workspace/app-mensajes/server
git init
git add server.js db.js crypto.js package.json package-lock.json render.yaml README.md DEPLOY.md .env.example .gitignore
git commit -m "Sakura Chat: servidor v1"
gh repo create sakura-chat --public --source=. --push
```

> `.env` y `data/` NO se suben (están en `.gitignore`): ahí están los
> secretos locales y la base de datos de pruebas.

## 2. Conseguir la DATABASE_URL de Neon (base de datos `sakurachat`)

La base de datos **ya existe**: proyecto Neon **"E & J"**
(`calm-pond-17046230`, región `aws-us-west-2`), branch `production`,
base de datos **`sakurachat`**, owner `neondb_owner`. Fue creada por API
el 2026-11-20. Solo falta su connection string:

**Opción A (consola Neon, recomendada):**
1. Abrir https://console.neon.tech → proyecto "E & J".
2. Branch `production` → **Connect** → Database: elegir **`sakurachat`**.
3. Copiar la connection string (`postgresql://.../sakurachat?sslmode=require`).
   Debe apuntar a `sakurachat`, NO a `neondb`.

**Opción B (terminal, con la CLI del conector):**
El script `neon-conn` toma la primera base de datos (`neondb`), así que
hay que pedir la URI con el nombre de base de datos explícito:
`GET /projects/calm-pond-17046230/connection_uri?branch_id=<branch_id>&database_name=sakurachat&role_name=neondb_owner`
(en `console.neon.tech/api/v2`, con la credencial `custom.neon`).

## 3. Crear el servicio en Render (Blueprint)

1. Abrir https://dashboard.render.com → **New → Blueprint** → conectar el
   repo `sakura-chat` de GitHub. Render lee `render.yaml` y crea el
   servicio **`sakura-chat-familia`** (plan free, `node server.js`,
   health check `/api/health`).
2. Cuando Render pida las variables de entorno:
   - `JWT_SECRET` y `ENCRYPTION_KEY`: se generan solas (`generateValue`).
   - `DATABASE_URL`: pegar la connection string del paso 2 (la de
     **`sakurachat`**). Es `sync: false`: hay que pegarla a mano.
3. **Deploy** → esperar a que el servicio esté "Live". La URL será
   `https://sakura-chat-familia.onrender.com` (la app Android ya la tiene como
   base por defecto).

> ⚠️ `ENCRYPTION_KEY` se genera una sola vez en el primer deploy. Si se
> cambia después, los mensajes ya guardados no se podrán descifrar.
> No rotarla.

## 4. Verificar que quedó en línea

```bash
curl https://sakura-chat-familia.onrender.com/api/health
# → {"ok":true}
```

Y en los logs de Render debe aparecer `Sakura Chat usando Postgres`.
Si aparece `usando SQLite local`, la `DATABASE_URL` no llegó bien:
en Render el disco es efímero y SQLite **no** persiste — no usarlo en
producción. Revisar en Render → Environment que la KEY sea exactamente
`DATABASE_URL` y el VALUE el `postgresql://...` completo, sin espacios
ni saltos de línea.

Después: registrar dos usuarios de prueba en la app Android, crear un
chat y enviar un mensaje. Las tablas se crean solas al primer arranque.

## Notas del plan gratis de Render

- El servicio se duerme tras ~15 min sin uso: la primera petición tarda
  30–60 s (cold start). La app debe reintentar, no cerrar la sesión.
- Los secretos (`JWT_SECRET`, `ENCRYPTION_KEY`, `DATABASE_URL`) viven
  solo en Render → Environment, nunca en el repo.
