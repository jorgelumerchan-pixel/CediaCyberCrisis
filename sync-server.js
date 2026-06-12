#!/usr/bin/env node
/* =====================================================================
   CYBERCRISIS TABLETOP · SERVIDOR DE SINCRONÍA MULTI-DISPOSITIVO
   CEDIA · v2.0 (endurecido) · Node.js puro, CERO dependencias npm.

   USO RECOMENDADO (HTTPS + token automáticos):
     node sync-server.js --https
       → puerto seguro 8443 (TLS 1.2+), certificado autofirmado generado
         con OpenSSL (SAN: localhost + IPs LAN), token aleatorio impreso
         e incrustado en la URL del QR; redirector 8080 → 8443.

   CERTIFICADO PROPIO (CA interna o Let's Encrypt con dominio):
     node sync-server.js --https --cert fullchain.pem --key privkey.pem [--hsts]

   OTRAS OPCIONES:
     --port N        puerto principal (def.: 8443 con --https, 8080 sin TLS)
     --http-port N   puerto del redirector HTTP→HTTPS (def.: 8080)
     --token CLAVE   token compartido fijo (def.: aleatorio por arranque)
     --no-token      desactiva el token (NO recomendado)
     --hsts          envía Strict-Transport-Security (solo con certificado
                     válido de CA: HSTS es por host e ignora el puerto)
     --reset         borra el estado persistido

   CONTROLES DE SEGURIDAD IMPLEMENTADOS:
     [C1] TLS 1.2 mínimo (tls.minVersion) en el puerto seguro 8443.
     [C2] Certificado: propio vía --cert/--key, o autofirmado ECDSA P-256
          autogenerado (825 días, SAN con las IPs LAN), clave con permisos 0600.
     [C3] Token de acceso obligatorio por defecto (aleatorio por sesión),
          comparación en tiempo constante (timingSafeEqual sobre SHA-256).
     [C4] Límite de tasa por IP (240 peticiones / 10 s → 429).
     [C5] Límite de cuerpo (2 MB) y topes de entidades en la fusión
          (200 ejercicios, 500 grupos, 2.000 participantes, 20.000
          respuestas, lecciones ≤ 2.000 caracteres) con validación de tipos.
     [C6] Cabeceras: X-Content-Type-Options, X-Frame-Options DENY,
          Referrer-Policy, Cache-Control no-store en /api, CSP del estático.
     [C7] Sin listado de directorios: solo se sirve index.html.
     [C8] Estado persistido con permisos 0600; el token nunca se persiste.
     [C9] Registro de intentos de autenticación fallidos con IP.
     Modelo de fusión determinista: ver comentarios de merge().
   ===================================================================== */
'use strict';
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const args = process.argv.slice(2);
const argVal = f => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : null; };
const HTTPS_ON = args.includes('--https') || (!!argVal('--cert') && !!argVal('--key'));
const PORT = parseInt(argVal('--port') || (HTTPS_ON ? '8443' : '8080'), 10);
const HTTP_REDIR_PORT = parseInt(argVal('--http-port') || '8080', 10);
const NO_TOKEN = args.includes('--no-token');
const TOKEN = NO_TOKEN ? '' : (argVal('--token') || crypto.randomBytes(5).toString('hex'));
const HSTS = args.includes('--hsts');
const DB_FILE = path.join(__dirname, 'cct-server-db.json');
const INDEX = path.join(__dirname, 'index.html');
const CERT_FILE = argVal('--cert') || path.join(__dirname, 'cert.pem');
const KEY_FILE = argVal('--key') || path.join(__dirname, 'key.pem');

if (args.includes('--reset')) { try { fs.unlinkSync(DB_FILE); console.log('Estado del servidor reiniciado.'); } catch (e) {} }

function lanIPs() {
  const ips = [];
  Object.values(os.networkInterfaces()).forEach(list => (list || []).forEach(n => { if (n.family === 'IPv4' && !n.internal) ips.push(n.address); }));
  return ips;
}

/* [C2] Certificado: usar el provisto o autogenerar uno autofirmado con SANs LAN */
function ensureCert() {
  if (fs.existsSync(CERT_FILE) && fs.existsSync(KEY_FILE)) return;
  const sans = ['DNS:localhost', 'IP:127.0.0.1', ...lanIPs().map(ip => 'IP:' + ip)].join(',');
  console.log('Generando certificado autofirmado (ECDSA P-256, 825 días)...');
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
      '-keyout', KEY_FILE, '-out', CERT_FILE, '-days', '825', '-nodes',
      '-subj', '/CN=CyberCrisis-Tabletop-LAN/O=CEDIA SOC-CSIRT',
      '-addext', 'subjectAltName=' + sans,
      '-addext', 'keyUsage=digitalSignature',
      '-addext', 'extendedKeyUsage=serverAuth'], { stdio: 'pipe' });
    try { fs.chmodSync(KEY_FILE, 0o600); fs.chmodSync(CERT_FILE, 0o644); } catch (e) {}
    console.log('Certificado: ' + CERT_FILE + ' · Clave (0600): ' + KEY_FILE);
    console.log('NOTA: al ser autofirmado, los navegadores mostrarán una advertencia la primera vez');
    console.log('      ("Avanzado → Continuar"). Para evitarla use un certificado de CA con --cert/--key.');
  } catch (e) {
    console.error('No se pudo generar el certificado (¿openssl instalado?): ' + e.message);
    console.error('Provea uno con: node sync-server.js --https --cert cert.pem --key key.pem');
    process.exit(1);
  }
}

let DB = { exercises: [], groups: [], participants: [], answers: [], lessons: {} };
let REV = 1;
try {
  const saved = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  DB = Object.assign(DB, saved.db || {});
  REV = saved.rev || 1;
  console.log('Estado restaurado: rev ' + REV + ' · ' + DB.exercises.length + ' ejercicio(s) · ' + DB.answers.length + ' respuesta(s).');
} catch (e) { /* primer arranque */ }

let saveTimer = null;
function persist() {                       /* [C8] persistencia con permisos restrictivos */
  if (saveTimer) clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    try { fs.writeFileSync(DB_FILE, JSON.stringify({ rev: REV, db: DB }), { mode: 0o600 }); }
    catch (e) { console.error('No se pudo persistir:', e.message); }
  }, 250);
}

/* [C3] Comparación de token en tiempo constante */
const TOKEN_DIGEST = crypto.createHash('sha256').update(TOKEN).digest();
function tokenOk(req) {
  if (!TOKEN) return true;
  const given = String(req.headers['x-sync-token'] || '');
  const d = crypto.createHash('sha256').update(given).digest();
  return crypto.timingSafeEqual(d, TOKEN_DIGEST);
}

/* [C4] Límite de tasa por IP: 240 peticiones por ventana de 10 s */
const RATE = new Map();
function rateLimited(ip) {
  const now = Date.now(); const w = RATE.get(ip);
  if (!w || now - w.t0 > 10000) { RATE.set(ip, { t0: now, n: 1 }); return false; }
  w.n++; return w.n > 240;
}
setInterval(() => { const now = Date.now(); RATE.forEach((w, ip) => { if (now - w.t0 > 30000) RATE.delete(ip); }); }, 30000).unref();

/* [C5] Validación y topes del estado entrante */
const LIMITS = { exercises: 200, groups: 500, participants: 2000, answers: 20000 };
function validClient(c) {
  if (typeof c !== 'object' || c === null) return 'estado no es objeto';
  for (const k of ['exercises', 'groups', 'participants', 'answers']) {
    if (c[k] != null && !Array.isArray(c[k])) return k + ' no es arreglo';
    if ((c[k] || []).length > LIMITS[k]) return k + ' excede el tope (' + LIMITS[k] + ')';
    for (const it of (c[k] || [])) {
      if (typeof it !== 'object' || it === null) return 'elemento inválido en ' + k;
      if (typeof it.id !== 'string' || it.id.length === 0 || it.id.length > 80) return 'id inválido en ' + k;
    }
  }
  for (const p of (c.participants || [])) {
    if (p.email != null && (typeof p.email !== 'string' || p.email.length > 200)) return 'email inválido';
    if (p.name != null && (typeof p.name !== 'string' || p.name.length > 200)) return 'nombre inválido';
  }
  if (c.lessons != null) {
    if (typeof c.lessons !== 'object') return 'lessons inválido';
    for (const arr of Object.values(c.lessons)) {
      if (!Array.isArray(arr)) return 'lessons inválido';
      for (const t of arr) if (typeof t !== 'string' || t.length > 2000) return 'lección demasiado larga';
    }
  }
  return null;
}

/* ------------------------- FUSIÓN DETERMINISTA -------------------------
   - answers inmutables: unión por id; una por participante+pregunta (gana la más antigua).
   - participants: upsert por id (mayor 'up'); correo único por ejercicio (gana el más antiguo).
   - Rol único por grupo: gana el roleAt más antiguo; el perdedor queda sin rol.
   - Máximo 5 por grupo: excedentes a grupo de desborde del mismo ejercicio.
   - exercises: upsert por id (estado gana por mayor 'up'). groups/lessons: unión.            */
function byId(arr) { const m = new Map(); (arr || []).forEach(x => { if (x && x.id) m.set(x.id, x); }); return m; }
function tsOf(x) { return (x && (x.up || x.createdAt)) || 0; }

function merge(client) {
  const c = Object.assign({ exercises: [], groups: [], participants: [], answers: [], lessons: {} }, client || {});
  const exM = byId(DB.exercises);
  (c.exercises || []).forEach(e => { const cur = exM.get(e.id); if (!cur || tsOf(e) >= tsOf(cur)) exM.set(e.id, e); });
  const grM = byId(DB.groups);
  (c.groups || []).forEach(g => { if (!grM.has(g.id)) grM.set(g.id, g); });
  const pM = byId(DB.participants);
  (c.participants || []).forEach(p => { const cur = pM.get(p.id); if (!cur || tsOf(p) >= tsOf(cur)) pM.set(p.id, p); });

  const dropP = new Set(); const seenMail = new Map();
  [...pM.values()].sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0)).forEach(p => {
    const k = p.exerciseId + '|' + String(p.email || '').toLowerCase();
    if (seenMail.has(k)) dropP.add(p.id); else seenMail.set(k, p);
  });
  dropP.forEach(id => pM.delete(id));

  const loserRole = new Set(); const claims = new Map();
  [...pM.values()].filter(p => p.roleId).sort((a, b) => (a.roleAt || a.createdAt || 0) - (b.roleAt || b.createdAt || 0)).forEach(p => {
    const k = p.groupId + '|' + p.roleId;
    if (claims.has(k)) { p.roleId = null; p.roleAt = null; p.up = Date.now(); loserRole.add(p.id); }
    else claims.set(k, p);
  });

  const byGroup = new Map();
  [...pM.values()].forEach(p => { if (!byGroup.has(p.groupId)) byGroup.set(p.groupId, []); byGroup.get(p.groupId).push(p); });
  byGroup.forEach((members, gid) => {
    if (members.length <= 5) return;
    const hasAns = id => DB.answers.some(x => x.participantId === id) || (c.answers || []).some(x => x.participantId === id);
    members.sort((a, b) => ((b.roleId ? 2 : 0) + (hasAns(b.id) ? 1 : 0)) - ((a.roleId ? 2 : 0) + (hasAns(a.id) ? 1 : 0)) || (a.createdAt || 0) - (b.createdAt || 0));
    const overflow = members.slice(5);
    const exId = (grM.get(gid) || {}).exerciseId || members[0].exerciseId;
    let target = [...grM.values()].find(g => g.exerciseId === exId && g.id !== gid &&
      [...pM.values()].filter(p => p.groupId === g.id).length < 5);
    if (!target) {
      target = { id: 'G-' + Date.now().toString(36) + crypto.randomBytes(3).toString('hex').toUpperCase(),
        exerciseId: exId, name: 'Grupo ' + ([...grM.values()].filter(g => g.exerciseId === exId).length + 1), createdAt: Date.now() };
      grM.set(target.id, target);
    }
    overflow.forEach(p => { p.groupId = target.id; p.roleId = null; p.roleAt = null; p.up = Date.now(); });
  });

  const aM = new Map();
  const valid = a => a && a.id && pM.has(a.participantId) && !loserRole.has(a.participantId);
  [...DB.answers, ...(c.answers || [])].filter(valid).sort((a, b) => (a.ts || 0) - (b.ts || 0)).forEach(a => {
    const k = a.participantId + '|' + a.questionId;
    if (!aM.has(k)) aM.set(k, a);
  });

  const lessons = Object.assign({}, DB.lessons);
  Object.entries(c.lessons || {}).forEach(([gid, arr]) => {
    lessons[gid] = [...new Set([...(lessons[gid] || []), ...(arr || [])])].slice(0, 200);
  });

  const next = {
    exercises: [...exM.values()].sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0)),
    groups: [...grM.values()].sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0)),
    participants: [...pM.values()].sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0)),
    answers: [...aM.values()].sort((a, b) => (a.ts || 0) - (b.ts || 0)),
    lessons
  };
  if (JSON.stringify(next) !== JSON.stringify(DB)) { DB = next; REV++; persist(); }
  return { rev: REV, db: DB };
}

/* ------------------------------ HTTP(S) ------------------------------ */
function baseHeaders(res, isApi) {        /* [C6] */
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,X-Sync-Token');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  if (isApi) res.setHeader('Cache-Control', 'no-store');
  if (HTTPS_ON && HSTS) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
}
function json(res, code, obj) { baseHeaders(res, true); res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(obj)); }

function handler(req, res) {
  const ip = (req.socket && req.socket.remoteAddress) || '?';
  if (rateLimited(ip)) return json(res, 429, { error: 'demasiadas peticiones' });   /* [C4] */
  const url = new URL(req.url, 'http://x');
  if (req.method === 'OPTIONS') { baseHeaders(res, true); res.writeHead(204); return res.end(); }
  if (url.pathname.startsWith('/api/')) {
    if (!tokenOk(req)) {                                                            /* [C3][C9] */
      console.log('[AUTH] token inválido desde ' + ip + ' → ' + url.pathname);
      return json(res, 401, { error: 'token inválido' });
    }
    if (url.pathname === '/api/info' && req.method === 'GET')
      return json(res, 200, { ips: lanIPs(), port: PORT, scheme: HTTPS_ON ? 'https' : 'http', tokenRequired: !!TOKEN, rev: REV });
    if (url.pathname === '/api/db' && req.method === 'GET') {
      const rev = parseInt(url.searchParams.get('rev') || '-1', 10);
      return rev === REV ? json(res, 200, { rev: REV, unchanged: true }) : json(res, 200, { rev: REV, db: DB });
    }
    if (url.pathname === '/api/merge' && req.method === 'POST') {
      let body = '';
      req.on('data', d => { body += d; if (body.length > 2e6) { json(res, 413, { error: 'cuerpo demasiado grande' }); req.destroy(); } });  /* [C5] */
      req.on('end', () => {
        if (res.writableEnded) return;
        try {
          const payload = JSON.parse(body || '{}');
          const c = payload.db || payload;
          const v = validClient(c);
          if (v) return json(res, 422, { error: 'estado inválido: ' + v });
          return json(res, 200, merge(c));
        } catch (e) { return json(res, 400, { error: 'JSON inválido' }); }
      });
      return;
    }
    return json(res, 404, { error: 'endpoint inexistente' });
  }
  if (url.pathname === '/' || url.pathname === '/index.html') {                     /* [C7] */
    try {
      const htmlDoc = fs.readFileSync(INDEX);
      baseHeaders(res, false);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(htmlDoc);
    } catch (e) { res.writeHead(500); return res.end('Coloque index.html junto a sync-server.js'); }
  }
  baseHeaders(res, false); res.writeHead(404); res.end('No encontrado');
}

let server;
if (HTTPS_ON) {
  ensureCert();
  server = https.createServer({
    key: fs.readFileSync(KEY_FILE),
    cert: fs.readFileSync(CERT_FILE),
    minVersion: 'TLSv1.2'                                                            /* [C1] */
  }, handler);
  // Redirector HTTP → HTTPS (conserva ruta y query, p. ej. el ?t= del QR)
  if (HTTP_REDIR_PORT && HTTP_REDIR_PORT !== PORT) {
    http.createServer((req, res) => {
      const host = String(req.headers.host || 'localhost').split(':')[0];
      res.writeHead(301, { Location: 'https://' + host + ':' + PORT + req.url });
      res.end();
    }).listen(HTTP_REDIR_PORT, '0.0.0.0', () => console.log(' Redirector http://*:' + HTTP_REDIR_PORT + ' → https://*:' + PORT));
  }
} else {
  server = http.createServer(handler);
}

server.listen(PORT, '0.0.0.0', () => {
  const scheme = HTTPS_ON ? 'https' : 'http';
  const q = TOKEN ? '/?t=' + TOKEN : '';
  console.log('================================================================');
  console.log(' CyberCrisis Tabletop · Servidor de sincronía (endurecido v2)');
  console.log('================================================================');
  console.log(' Modo: ' + (HTTPS_ON ? 'HTTPS (TLS ≥1.2) en puerto seguro ' + PORT : 'HTTP sin cifrar en ' + PORT + '  ⚠ use --https'));
  console.log(' Abra en cada dispositivo (el token va incluido en la URL/QR):');
  lanIPs().forEach(ipAddr => console.log('   → ' + scheme + '://' + ipAddr + ':' + PORT + q));
  console.log('   → ' + scheme + '://localhost:' + PORT + q + '  (este equipo)');
  console.log(TOKEN ? ' Token de la sesión: ' + TOKEN : ' ⚠ Token DESACTIVADO (--no-token): cualquier equipo de la red puede leer/escribir.');
  console.log(' Estado persistido (0600): ' + DB_FILE);
});

module.exports = { merge, validClient, _state: () => ({ DB, REV, TOKEN, HTTPS_ON, PORT }) };
