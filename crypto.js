// Sakura Chat 🌸 — cifrado en reposo (AES-256-GCM, node:crypto)
// Cada mensaje se cifra con un IV aleatorio nuevo; se guardan iv + texto cifrado
// (base64) en la base de datos. NUNCA se guarda el texto plano.
//
// LÍMITE HONESTO: esto es cifrado en reposo con una clave que guarda el
// servidor. El transporte va por TLS (HTTPS en Render). Esto NO es cifrado
// de extremo a extremo: el servidor puede descifrar los mensajes.
const crypto = require('crypto');

function getKey() {
  const raw = (process.env.ENCRYPTION_KEY || '').trim();
  if (!raw) {
    // Solo desarrollo local: clave efímera por arranque (los mensajes viejos
    // no se podrán descifrar tras reiniciar sin ENCRYPTION_KEY fija).
    console.warn('Sakura Chat AVISO: ENCRYPTION_KEY no está configurada; usando clave efímera (solo desarrollo local).');
    return crypto.randomBytes(32);
  }
  // 32 bytes en hex (64 caracteres hex) → se usa tal cual.
  if (/^[0-9a-fA-F]{64}$/.test(raw)) return Buffer.from(raw, 'hex');
  // Cualquier otro valor (p. ej. el generateValue de Render) → se deriva
  // una clave de 32 bytes con SHA-256, de forma determinista.
  return crypto.createHash('sha256').update(raw, 'utf8').digest();
}

const KEY = getKey();

// Cifra un string UTF-8 → { iv, data } en base64 (tag de 16 bytes al final de data)
function encrypt(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv: iv.toString('base64'), data: Buffer.concat([enc, tag]).toString('base64') };
}

// Descifra { iv, data } en base64 → string UTF-8
function decrypt(ivB64, dataB64) {
  const iv = Buffer.from(ivB64, 'base64');
  const buf = Buffer.from(dataB64, 'base64');
  const tag = buf.subarray(buf.length - 16);
  const enc = buf.subarray(0, buf.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
}

module.exports = { encrypt, decrypt };
