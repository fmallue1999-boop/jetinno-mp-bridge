'use strict';

/**
 * ============================================================
 *  JETINNO <-> MERCADOPAGO — PLATAFORMA MULTI-CLIENTE
 * ============================================================
 * - Sirve a MÚLTIPLES clientes: cada uno con su cuenta IOT de
 *   Jetinno (username+apikey) y su propia cuenta de MercadoPago.
 * - Panel de administración en /admin (protegido con contraseña).
 * - Base de datos Postgres (DATABASE_URL). Sin base, funciona en
 *   modo memoria sembrado con las variables de entorno (AR1362).
 * - Tokens de MercadoPago cifrados (AES-256-GCM) en la base.
 *
 * ENV:
 *   JETINNO_USERNAME, JETINNO_APIKEY   -> cliente semilla (tu AR1362)
 *   MP_ACCESS_TOKEN, MP_USER_ID        -> MercadoPago del cliente semilla
 *   MP_NOTIFICATION_URL                -> https://<host>/mp/webhook
 *   ADMIN_PASSWORD                     -> contraseña del panel /admin
 *   ENCRYPTION_KEY                     -> clave para cifrar tokens (frase larga)
 *   DATABASE_URL                       -> Postgres (opcional pero recomendado)
 */

const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '256kb' }));

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const BASE_NOTIFY = process.env.MP_NOTIFICATION_URL || '';

// ================= Cifrado de credenciales =================
const ENC_KEY = crypto.createHash('sha256')
  .update(process.env.ENCRYPTION_KEY || 'CAMBIAME-clave-por-defecto-insegura')
  .digest();
function encrypt(text) {
  if (!text) return '';
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const enc = Buffer.concat([cipher.update(String(text), 'utf8'), cipher.final()]);
  return `${iv.toString('hex')}:${cipher.getAuthTag().toString('hex')}:${enc.toString('hex')}`;
}
function decrypt(payload) {
  if (!payload) return '';
  try {
    const [ivh, tagh, dh] = String(payload).split(':');
    const decipher = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, Buffer.from(ivh, 'hex'));
    decipher.setAuthTag(Buffer.from(tagh, 'hex'));
    return Buffer.concat([decipher.update(Buffer.from(dh, 'hex')), decipher.final()]).toString('utf8');
  } catch { return ''; }
}

// ================= Base de datos (opcional) =================
let pool = null;
let dbReady = false;
async function initDb() {
  if (!process.env.DATABASE_URL) { console.log('[DB] Sin DATABASE_URL: modo memoria (los cambios del panel se pierden al reiniciar).'); return; }
  try {
    const { Pool } = require('pg');
    pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
    await pool.query(`CREATE TABLE IF NOT EXISTS clients (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      jetinno_username TEXT UNIQUE NOT NULL,
      jetinno_apikey_enc TEXT NOT NULL,
      mp_user_id TEXT DEFAULT '',
      mp_token_enc TEXT DEFAULT '',
      active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT now()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS machines (
      id SERIAL PRIMARY KEY,
      device_no TEXT UNIQUE NOT NULL,
      client_id INTEGER REFERENCES clients(id) ON DELETE CASCADE,
      label TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT now()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS orders (
      order_no TEXT PRIMARY KEY,
      client_username TEXT,
      device_no TEXT,
      amount_cents INTEGER,
      product TEXT DEFAULT '',
      status TEXT DEFAULT 'PENDING',
      mp_payment_id TEXT DEFAULT '',
      notify_url TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT now(),
      updated_at TIMESTAMPTZ DEFAULT now()
    )`);
    await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS mp_username TEXT DEFAULT ''`).catch(() => {});
    dbReady = true;
    console.log('[DB] Postgres conectado y tablas listas.');
    await seedFromEnv();
  } catch (e) {
    console.error('[DB] Error conectando a Postgres:', e.message, '— sigo en modo memoria.');
    pool = null; dbReady = false;
  }
}

// ================= Clientes (memoria + DB) =================
// Cliente semilla desde variables de entorno (tu cuenta actual).
const seedClient = () => (process.env.JETINNO_USERNAME ? {
  id: 0,
  name: 'Principal (env)',
  jetinno_username: process.env.JETINNO_USERNAME,
  jetinno_apikey: process.env.JETINNO_APIKEY || '',
  mp_user_id: process.env.MP_USER_ID || '',
  mp_token: process.env.MP_ACCESS_TOKEN || '',
  active: true,
} : null);

const memClients = new Map(); // username -> client (modo memoria)
const s0 = seedClient(); if (s0) memClients.set(s0.jetinno_username, s0);

async function seedFromEnv() {
  const s = seedClient();
  if (!s || !dbReady) return;
  const r = await pool.query('SELECT id FROM clients WHERE jetinno_username=$1', [s.jetinno_username]);
  if (r.rows.length === 0) {
    await pool.query(
      'INSERT INTO clients(name, jetinno_username, jetinno_apikey_enc, mp_user_id, mp_token_enc, active) VALUES($1,$2,$3,$4,$5,TRUE)',
      [s.name, s.jetinno_username, encrypt(s.jetinno_apikey), s.mp_user_id, encrypt(s.mp_token)]
    );
    console.log(`[DB] Cliente semilla migrado: ${s.jetinno_username}`);
  }
}

const clientCache = new Map(); // username -> {client, ts}
async function getClient(username) {
  if (!username) return null;
  const hit = clientCache.get(username);
  if (hit && Date.now() - hit.ts < 60000) return hit.client;
  let client = null;
  if (dbReady) {
    const r = await pool.query('SELECT * FROM clients WHERE jetinno_username=$1 AND active=TRUE', [username]);
    if (r.rows.length) {
      const row = r.rows[0];
      client = {
        id: row.id, name: row.name, jetinno_username: row.jetinno_username,
        jetinno_apikey: decrypt(row.jetinno_apikey_enc),
        mp_user_id: row.mp_user_id, mp_token: decrypt(row.mp_token_enc), active: row.active,
      };
    }
  } else {
    client = memClients.get(username) || null;
  }
  clientCache.set(username, { client, ts: Date.now() });
  return client;
}

// Ruteo por máquina: si la máquina está asignada a un cliente en la tabla
// "machines", el dinero va al MercadoPago de ESE cliente (aunque la petición
// llegue autenticada como la cuenta nivel 1, ej. AR1362).
const machineOwnerCache = new Map(); // deviceNo -> {username|null, ts}
async function resolveMpOwner(authClient, deviceNo) {
  const dev = String(deviceNo || '');
  if (!dev || !dbReady) return authClient;
  const hit = machineOwnerCache.get(dev);
  let ownerUsername;
  if (hit && Date.now() - hit.ts < 60000) {
    ownerUsername = hit.username;
  } else {
    const r = await pool.query(
      'SELECT c.jetinno_username u FROM machines m JOIN clients c ON c.id=m.client_id WHERE m.device_no=$1 AND c.active=TRUE', [dev]
    ).catch(() => ({ rows: [] }));
    ownerUsername = r.rows.length ? r.rows[0].u : null;
    machineOwnerCache.set(dev, { username: ownerUsername, ts: Date.now() });
  }
  if (!ownerUsername || ownerUsername === authClient.jetinno_username) return authClient;
  const owner = await getClient(ownerUsername);
  return owner && owner.mp_token ? owner : authClient;
}

// ================= Firma MD5 (manual Jetinno A5) =================
function buildSignString(params, nonce) {
  const keys = Object.keys(params)
    .filter((k) => k !== 'sign' && k !== 'data' && k !== 'nonce')
    .filter((k) => params[k] !== null && params[k] !== undefined && params[k] !== '')
    .sort();
  let str = keys.map((k) => `${k}=${params[k]}`).join('&');
  if (nonce) str = `${nonce}${str}`;
  return str;
}
function sign(params, apikey, nonce) {
  return crypto.createHash('md5').update(`${buildSignString(params, nonce)}${apikey}`, 'utf8').digest('hex').toUpperCase();
}
function flatten(message) { const { data, sign: _s, ...top } = message; return { ...top, ...(data || {}) }; }
function verify(message, apikey, { extraSignedFields = [], optionalFields = [] } = {}) {
  const flat = flatten(message);
  for (const f of optionalFields) if (!extraSignedFields.includes(f)) delete flat[f];
  return sign(flat, apikey, message.nonce) === String(message.sign || '').toUpperCase();
}

// ================= MercadoPago (por cliente) =================
const MP_BASE = 'https://api.mercadopago.com';
async function mpFetch(client, path, { method = 'GET', body } = {}) {
  const res = await fetch(`${MP_BASE}${path}`, {
    method,
    headers: { Authorization: `Bearer ${client.mp_token}`, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json; try { json = text ? JSON.parse(text) : {}; } catch { json = { raw: text }; }
  if (!res.ok) { const e = new Error(`MP ${res.status} ${path}: ${text.slice(0, 300)}`); e.status = res.status; e.body = json; throw e; }
  return json;
}

const storeExtId = (dev) => `JETINNOSTORE${dev}`;
const posExtId = (dev) => `JETINNOPOS${dev}`;
const posCache = new Map(); // `${username}:${dev}` -> posExternalId

async function ensurePos(client, deviceNo) {
  const dev = String(deviceNo || '0');
  const key = `${client.jetinno_username}:${dev}`;
  if (posCache.has(key)) return posCache.get(key);
  if (!client.mp_user_id) throw new Error(`Cliente ${client.jetinno_username} sin mp_user_id`);
  const found = await mpFetch(client, `/pos?external_id=${encodeURIComponent(posExtId(dev))}`);
  let pos = (found.results || []).find((p) => p.external_id === posExtId(dev)) || null;
  if (!pos) {
    const rs = await mpFetch(client, `/users/${client.mp_user_id}/stores/search`);
    let storeId = ((rs.results || []).find((s) => s.external_id === storeExtId(dev)) || {}).id;
    if (!storeId) {
      const st = await mpFetch(client, `/users/${client.mp_user_id}/stores`, {
        method: 'POST',
        body: {
          name: `Jetinno ${dev}`, external_id: storeExtId(dev),
          location: { street_number: '55', street_name: 'Alberti', city_name: 'La Plata', state_name: 'Buenos Aires', latitude: -34.9205, longitude: -57.9536 },
        },
      });
      storeId = st.id;
    }
    pos = await mpFetch(client, '/pos', {
      method: 'POST',
      body: { name: `Caja Jetinno ${dev}`, fixed_amount: false, store_id: storeId, external_id: posExtId(dev), category: 621102 },
    });
    console.log(`[MP:${client.jetinno_username}] Caja creada para ${dev} (store ${storeId})`);
  }
  posCache.set(key, posExtId(dev));
  return posExtId(dev);
}

async function createQrOrder(client, p) {
  if (!client.mp_token) { // sin MercadoPago -> QR simulado (modo prueba del cliente)
    return { qrData: `00020101021143MOCKQR-${p.orderNo}`.slice(0, 300), mpOrderId: `mock-${p.orderNo}` };
  }
  const posExt = await ensurePos(client, p.deviceNo);
  const amount = Number(p.amount);
  const notif = BASE_NOTIFY ? `${BASE_NOTIFY}?u=${encodeURIComponent(client.jetinno_username)}` : undefined;
  const data = await mpFetch(client, `/instore/orders/qr/seller/collectors/${client.mp_user_id}/pos/${encodeURIComponent(posExt)}/qrs`, {
    method: 'POST',
    body: {
      external_reference: p.orderNo,
      title: p.title || `Orden ${p.orderNo}`,
      description: p.title || `Orden ${p.orderNo}`,
      notification_url: notif,
      total_amount: amount,
      items: [{ title: p.title || `Producto ${p.orderNo}`, quantity: 1, unit_price: amount, unit_measure: 'unit', total_amount: amount }],
    },
  });
  return { qrData: (data.qr_data || '').toString(), mpOrderId: data.in_store_order_id || p.orderNo };
}

// ================= Órdenes (memoria + DB write-through) =================
const memOrders = new Map(); // orderNo -> {username, deviceNo, amountCents, notifyUrl, mpPaymentId, status, product}
async function saveOrder(o) {
  memOrders.set(o.orderNo, o);
  if (dbReady) {
    await pool.query(
      `INSERT INTO orders(order_no, client_username, mp_username, device_no, amount_cents, product, status, notify_url)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8)
       ON CONFLICT (order_no) DO UPDATE SET status=$7, updated_at=now()`,
      [o.orderNo, o.username, o.mpUsername || o.username, o.deviceNo, o.amountCents, o.product || '', o.status, o.notifyUrl || '']
    ).catch((e) => console.error('[DB] saveOrder', e.message));
  }
}
async function updateOrder(orderNo, fields) {
  const o = memOrders.get(orderNo);
  if (o) Object.assign(o, fields);
  if (dbReady) {
    await pool.query(
      'UPDATE orders SET status=COALESCE($2,status), mp_payment_id=COALESCE($3,mp_payment_id), updated_at=now() WHERE order_no=$1',
      [orderNo, fields.status || null, fields.mpPaymentId || null]
    ).catch((e) => console.error('[DB] updateOrder', e.message));
  }
  return o;
}
async function getOrder(orderNo) {
  if (memOrders.has(orderNo)) return memOrders.get(orderNo);
  if (dbReady) {
    const r = await pool.query('SELECT * FROM orders WHERE order_no=$1', [orderNo]);
    if (r.rows.length) {
      const row = r.rows[0];
      const o = { orderNo: row.order_no, username: row.client_username, mpUsername: row.mp_username || row.client_username, deviceNo: row.device_no, amountCents: row.amount_cents, notifyUrl: row.notify_url, mpPaymentId: row.mp_payment_id, status: row.status, product: row.product };
      memOrders.set(orderNo, o);
      return o;
    }
  }
  return null;
}

// ================= Helpers de respuesta Jetinno =================
function ts() {
  const d = new Date(), p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}
function ok(res, client, data) {
  const body = { returnCode: 'SUCCESS', msg: 'SUCCESS', time: ts() };
  if (data) { body.data = data; body.sign = sign({ username: client.jetinno_username, time: body.time, ...data }, client.jetinno_apikey); }
  res.json(body);
}
function fail(res, msg = 'FAIL') { res.json({ returnCode: 'FAIL', msg, time: ts() }); }

async function authClient(req, res, opts) {
  const username = req.body.username;
  const client = await getClient(username);
  if (!client) { fail(res, 'USER_NOT_EXIST'); return null; }
  if (!verify(req.body, client.jetinno_apikey, opts)) { fail(res, 'SIGN_ERROR'); return null; }
  return client;
}

// ================= Endpoints Jetinno =================
app.post('/getQrCode', async (req, res) => {
  const d = req.body.data || {};
  console.log(`[getQrCode] user=${req.body.username} device=${d.deviceNo} order=${d.orderNo} cents=${d.orderAmount}`);
  try {
    const client = await authClient(req, res, { optionalFields: ['payType', 'merchantNo', 'attach'] });
    if (!client) return;
    const amountCents = parseInt(d.orderAmount, 10);
    const mpOwner = await resolveMpOwner(client, d.deviceNo); // dueño del dinero (por máquina)
    if (mpOwner.jetinno_username !== client.jetinno_username) console.log(`[getQrCode] máquina ${d.deviceNo} -> MP de ${mpOwner.jetinno_username}`);
    const { qrData } = await createQrOrder(mpOwner, { orderNo: d.orderNo, amount: amountCents / 100, title: d.productName, deviceNo: d.deviceNo });
    await saveOrder({ orderNo: d.orderNo, username: client.jetinno_username, mpUsername: mpOwner.jetinno_username, deviceNo: d.deviceNo, amountCents, notifyUrl: d.notifyUrl, product: d.productName || '', status: 'PENDING', mpPaymentId: null });
    console.log(`[getQrCode] OK qr len=${qrData.length}`);
    ok(res, client, { deviceNo: d.deviceNo, orderNo: d.orderNo, qrCode: qrData });
  } catch (e) { console.error('[getQrCode] ERROR', e.message); fail(res, 'SYSTEM_ERROR'); }
});

app.post('/payBarCode', async (req, res) => {
  try {
    const client = await authClient(req, res, { optionalFields: ['merchantNo', 'attach'] });
    if (!client) return;
    const d = req.body.data || {};
    await saveOrder({ orderNo: d.orderNo, username: client.jetinno_username, deviceNo: d.deviceNo, amountCents: parseInt(d.orderAmount, 10), notifyUrl: d.notifyUrl, product: d.productName || '', status: 'PAYING', mpPaymentId: null });
    ok(res, client, { deviceNo: d.deviceNo, orderNo: d.orderNo, payStatus: 'PAYING' });
  } catch (e) { console.error('[payBarCode]', e.message); fail(res, 'SYSTEM_ERROR'); }
});

app.post('/refund', async (req, res) => {
  try {
    const client = await authClient(req, res, { optionalFields: ['merchantNo', 'platBillNo', 'attach'] });
    if (!client) return;
    const d = req.body.data || {};
    const o = await getOrder(d.orderNo);
    const mpc = o ? (await getClient(o.mpUsername || o.username)) || client : client; // el reembolso sale del MP dueño de la orden
    if (o && o.mpPaymentId && mpc.mp_token) {
      await mpFetch(mpc, `/v1/payments/${o.mpPaymentId}/refunds`, { method: 'POST', body: { amount: parseInt(d.refundAmount, 10) / 100 } });
      await updateOrder(d.orderNo, { status: 'REFUNDED' });
    }
    ok(res, client, { deviceNo: d.deviceNo, orderNo: d.orderNo, refundState: 'SUCCESS' });
  } catch (e) {
    console.error('[refund]', e.message);
    const client = await getClient(req.body.username);
    if (client) ok(res, client, { deviceNo: req.body?.data?.deviceNo, orderNo: req.body?.data?.orderNo, refundState: 'ERROR' });
    else fail(res, 'SYSTEM_ERROR');
  }
});

app.post('/productdone', async (req, res) => {
  try {
    const client = await authClient(req, res, { optionalFields: ['merchantNo', 'platBillNo', 'attach'] });
    if (!client) return;
    const d = req.body.data || {};
    if (d.isFinish === 'ERROR') {
      const o = await getOrder(d.orderNo);
      const mpc = o ? (await getClient(o.mpUsername || o.username)) || client : client;
      if (o && o.mpPaymentId && mpc.mp_token) {
        mpFetch(mpc, `/v1/payments/${o.mpPaymentId}/refunds`, { method: 'POST', body: {} })
          .then(() => updateOrder(d.orderNo, { status: 'REFUNDED' }))
          .catch((e) => console.error('refund auto', e.message));
        console.log(`[productdone] entrega fallida ${d.orderNo} -> reembolso (MP de ${mpc.jetinno_username})`);
      }
    } else {
      await updateOrder(d.orderNo, { status: 'DELIVERED' });
    }
    res.json({ returnCode: 'SUCCESS', msg: 'SUCCESS', time: ts() });
  } catch (e) { console.error('[productdone]', e.message); fail(res, 'SYSTEM_ERROR'); }
});

// ================= Webhook MercadoPago (con ?u=<username>) =================
app.post('/mp/webhook', async (req, res) => {
  res.sendStatus(200);
  try {
    const q = req.query || {}; const b = req.body || {};
    const username = q.u || '';
    const client = await getClient(username) || seedClient();
    if (!client || !client.mp_token) return;
    const type = b.type || q.type || q.topic;
    let orderNo = null, payId = null;
    if (type === 'payment') {
      payId = b.data?.id || q['data.id'] || q.id;
      if (payId) {
        const pay = await mpFetch(client, `/v1/payments/${payId}`);
        if (pay.status === 'approved') orderNo = pay.external_reference;
      }
    } else if (type === 'merchant_order') {
      const moId = b.data?.id || q.id;
      if (moId) {
        const mo = await mpFetch(client, `/merchant_orders/${moId}`);
        const approved = (mo.payments || []).some((p) => p.status === 'approved');
        if (mo.order_status === 'paid' || approved) orderNo = mo.external_reference;
      }
    }
    console.log(`[mp/webhook] u=${username} type=${type} orderNo=${orderNo}`);
    if (!orderNo) return;
    const o = await getOrder(orderNo);
    if (!o || o.status === 'PAID' || o.status === 'DELIVERED') return; // idempotencia
    await updateOrder(orderNo, { status: 'PAID', mpPaymentId: payId ? String(payId) : undefined });
    // El aviso a Jetinno se firma con la cuenta que autenticó la orden (nivel 1, ej. AR1362)
    const jet = await getClient(o.username) || client;
    await notifyJetinno(jet, o, orderNo, 'PAYSUCCESS', payId);
  } catch (e) { console.error('[mp/webhook]', e.message); }
});

async function notifyJetinno(client, order, orderNo, payStatus, platBillNo) {
  const time = ts();
  const data = { deviceNo: order.deviceNo, orderNo, orderAmount: String(order.amountCents), payType: '1001', payStatus };
  if (platBillNo) data.platBillNo = String(platBillNo);
  const s = sign({ username: client.jetinno_username, time, deviceNo: data.deviceNo, orderNo: data.orderNo, orderAmount: data.orderAmount, payType: data.payType, payStatus: data.payStatus }, client.jetinno_apikey);
  const r = await fetch(order.notifyUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: client.jetinno_username, time, sign: s, data }) });
  console.log(`[callback->Jetinno] ${orderNo} ${r.status} ${await r.text()}`);
}

// ================= Diagnóstico =================
app.get('/', (_req, res) => res.send('Jetinno <-> MercadoPago bridge OK (multi-cliente)'));
app.get('/health', async (_req, res) => {
  res.json({ ok: true, db: dbReady, seed: !!seedClient(), adminConfigured: !!ADMIN_PASSWORD });
});
app.get('/testqr', async (req, res) => {
  try {
    const username = req.query.u || (seedClient() || {}).jetinno_username;
    const client = await getClient(username);
    if (!client) return res.status(404).json({ ok: false, error: 'cliente no encontrado' });
    const r = await createQrOrder(client, { orderNo: 'TEST' + Date.now(), amount: Number(req.query.amount || 1), title: 'Prueba', deviceNo: req.query.device || '173840' });
    res.json({ ok: true, cliente: username, qrLen: (r.qrData || '').length, qrData: r.qrData });
  } catch (e) { res.status(500).json({ ok: false, error: e.message, body: e.body }); }
});

// ================= PANEL DE ADMINISTRACIÓN =================
function adminAuth(req, res, next) {
  if (!ADMIN_PASSWORD) return res.status(503).send('Configura ADMIN_PASSWORD en las variables de entorno para usar el panel.');
  const hdr = req.headers.authorization || '';
  if (hdr.startsWith('Basic ')) {
    const [, pass] = Buffer.from(hdr.slice(6), 'base64').toString('utf8').split(':');
    if (pass === ADMIN_PASSWORD) return next();
  }
  res.set('WWW-Authenticate', 'Basic realm="Panel Jetinno-MP"');
  res.status(401).send('Autenticacion requerida');
}

// --- API del panel ---
app.get('/admin/api/status', adminAuth, async (_req, res) => {
  let nClients = 0, nMachines = 0, nOrders = 0;
  if (dbReady) {
    nClients = Number((await pool.query('SELECT COUNT(*) c FROM clients')).rows[0].c);
    nMachines = Number((await pool.query('SELECT COUNT(*) c FROM machines')).rows[0].c);
    nOrders = Number((await pool.query('SELECT COUNT(*) c FROM orders')).rows[0].c);
  } else { nClients = memClients.size; nOrders = memOrders.size; }
  res.json({ db: dbReady, clients: nClients, machines: nMachines, orders: nOrders, webhookBase: BASE_NOTIFY });
});

app.get('/admin/api/clients', adminAuth, async (_req, res) => {
  const out = [];
  if (dbReady) {
    const r = await pool.query('SELECT id,name,jetinno_username,mp_user_id,active,created_at, (mp_token_enc<>\'\') AS has_mp, (jetinno_apikey_enc<>\'\') AS has_key FROM clients ORDER BY id');
    for (const c of r.rows) out.push({ id: c.id, name: c.name, username: c.jetinno_username, mpUserId: c.mp_user_id, hasMp: c.has_mp, hasKey: c.has_key, active: c.active });
  } else {
    for (const c of memClients.values()) out.push({ id: c.id, name: c.name, username: c.jetinno_username, mpUserId: c.mp_user_id, hasMp: !!c.mp_token, hasKey: !!c.jetinno_apikey, active: c.active });
  }
  res.json(out);
});

app.post('/admin/api/clients', adminAuth, async (req, res) => {
  const { name, username, apikey, mpUserId, mpToken } = req.body || {};
  if (!name || !username) return res.status(400).json({ error: 'Faltan: nombre y username' });
  try {
    if (dbReady) {
      await pool.query(
        `INSERT INTO clients(name, jetinno_username, jetinno_apikey_enc, mp_user_id, mp_token_enc, active)
         VALUES($1,$2,$3,$4,$5,TRUE)
         ON CONFLICT (jetinno_username) DO UPDATE SET name=$1,
           jetinno_apikey_enc=CASE WHEN $3<>'' THEN $3 ELSE clients.jetinno_apikey_enc END,
           mp_user_id=CASE WHEN $4<>'' THEN $4 ELSE clients.mp_user_id END,
           mp_token_enc=CASE WHEN $5<>'' THEN $5 ELSE clients.mp_token_enc END, active=TRUE`,
        [name, username, apikey ? encrypt(apikey) : '', mpUserId || '', mpToken ? encrypt(mpToken) : '']
      );
    } else {
      memClients.set(username, { id: memClients.size, name, jetinno_username: username, jetinno_apikey: apikey || '', mp_user_id: mpUserId || '', mp_token: mpToken || '', active: true });
    }
    clientCache.delete(username); machineOwnerCache.clear();
    clientCache.delete(username);
    res.json({ ok: true, warning: dbReady ? null : 'SIN BASE DE DATOS: este cliente se pierde al reiniciar el servidor.' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/admin/api/clients/:username/toggle', adminAuth, async (req, res) => {
  const u = req.params.username;
  if (dbReady) await pool.query('UPDATE clients SET active = NOT active WHERE jetinno_username=$1', [u]);
  else { const c = memClients.get(u); if (c) c.active = !c.active; }
  clientCache.delete(u);
  res.json({ ok: true });
});

app.get('/admin/api/machines', adminAuth, async (_req, res) => {
  if (!dbReady) return res.json([]);
  const r = await pool.query('SELECT m.id, m.device_no, m.label, c.jetinno_username AS username, c.name AS client_name FROM machines m LEFT JOIN clients c ON c.id=m.client_id ORDER BY m.id');
  res.json(r.rows);
});
app.post('/admin/api/machines', adminAuth, async (req, res) => {
  const { deviceNo, username, label } = req.body || {};
  if (!deviceNo || !username) return res.status(400).json({ error: 'Faltan deviceNo y username' });
  if (!dbReady) return res.status(400).json({ error: 'El registro de máquinas requiere base de datos' });
  const c = await pool.query('SELECT id FROM clients WHERE jetinno_username=$1', [username]);
  if (!c.rows.length) return res.status(404).json({ error: 'Cliente no encontrado' });
  await pool.query(
    'INSERT INTO machines(device_no, client_id, label) VALUES($1,$2,$3) ON CONFLICT (device_no) DO UPDATE SET client_id=$2, label=$3',
    [String(deviceNo), c.rows[0].id, label || '']
  );
  machineOwnerCache.delete(String(deviceNo));
  res.json({ ok: true });
});
app.post('/admin/api/machines/:id/delete', adminAuth, async (req, res) => {
  if (dbReady) await pool.query('DELETE FROM machines WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

// Estadísticas de cobros (estados PAID y DELIVERED cuentan como cobrado)
const TZ = 'America/Argentina/Buenos_Aires';
app.get('/admin/api/stats', adminAuth, async (_req, res) => {
  const empty = { hoy: { n: 0, cents: 0 }, semana: { n: 0, cents: 0 }, mes: { n: 0, cents: 0 }, total: { n: 0, cents: 0 }, reembolsos: { n: 0, cents: 0 }, porMaquina: [], porCliente: [], porDia: [] };
  if (!dbReady) {
    // Modo memoria: agregación simple del Map
    for (const o of memOrders.values()) {
      if (o.status === 'PAID' || o.status === 'DELIVERED') { empty.total.n++; empty.total.cents += o.amountCents || 0; }
      if (o.status === 'REFUNDED') { empty.reembolsos.n++; empty.reembolsos.cents += o.amountCents || 0; }
    }
    return res.json(empty);
  }
  try {
    const paid = "status IN ('PAID','DELIVERED')";
    const localDate = `(created_at AT TIME ZONE '${TZ}')::date`;
    const todayLocal = `(now() AT TIME ZONE '${TZ}')::date`;
    const q = async (sql, params = []) => (await pool.query(sql, params)).rows;
    const [hoy] = await q(`SELECT COUNT(*) n, COALESCE(SUM(amount_cents),0) c FROM orders WHERE ${paid} AND ${localDate} = ${todayLocal}`);
    const [semana] = await q(`SELECT COUNT(*) n, COALESCE(SUM(amount_cents),0) c FROM orders WHERE ${paid} AND created_at >= now() - interval '7 days'`);
    const [mes] = await q(`SELECT COUNT(*) n, COALESCE(SUM(amount_cents),0) c FROM orders WHERE ${paid} AND date_trunc('month', created_at AT TIME ZONE '${TZ}') = date_trunc('month', now() AT TIME ZONE '${TZ}')`);
    const [total] = await q(`SELECT COUNT(*) n, COALESCE(SUM(amount_cents),0) c FROM orders WHERE ${paid}`);
    const [reem] = await q(`SELECT COUNT(*) n, COALESCE(SUM(amount_cents),0) c FROM orders WHERE status='REFUNDED'`);
    const porMaquina = await q(`SELECT device_no, COUNT(*) n, COALESCE(SUM(amount_cents),0) c FROM orders WHERE ${paid} GROUP BY device_no ORDER BY c DESC`);
    const porCliente = await q(`SELECT COALESCE(NULLIF(mp_username,''), client_username) AS client_username, COUNT(*) n, COALESCE(SUM(amount_cents),0) c FROM orders WHERE ${paid} GROUP BY 1 ORDER BY c DESC`);
    const porDia = await q(`SELECT ${localDate} d, COUNT(*) n, COALESCE(SUM(amount_cents),0) c FROM orders WHERE ${paid} AND created_at >= now() - interval '14 days' GROUP BY 1 ORDER BY 1`);
    res.json({
      hoy: { n: +hoy.n, cents: +hoy.c }, semana: { n: +semana.n, cents: +semana.c },
      mes: { n: +mes.n, cents: +mes.c }, total: { n: +total.n, cents: +total.c },
      reembolsos: { n: +reem.n, cents: +reem.c },
      porMaquina: porMaquina.map((r) => ({ device: r.device_no, n: +r.n, cents: +r.c })),
      porCliente: porCliente.map((r) => ({ username: r.client_username, n: +r.n, cents: +r.c })),
      porDia: porDia.map((r) => ({ dia: r.d, n: +r.n, cents: +r.c })),
    });
  } catch (e) { console.error('[stats]', e.message); res.status(500).json({ error: e.message }); }
});

app.get('/admin/api/orders', adminAuth, async (_req, res) => {
  if (dbReady) {
    const r = await pool.query('SELECT order_no, client_username, device_no, amount_cents, product, status, mp_payment_id, created_at FROM orders ORDER BY created_at DESC LIMIT 100');
    return res.json(r.rows);
  }
  const out = [];
  for (const [orderNo, o] of memOrders) out.push({ order_no: orderNo, client_username: o.username, device_no: o.deviceNo, amount_cents: o.amountCents, product: o.product, status: o.status, mp_payment_id: o.mpPaymentId });
  res.json(out.slice(-100).reverse());
});

// --- Página del panel ---
app.get('/admin', adminAuth, (_req, res) => {
  res.type('html').send(`<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Panel Jetinno + MercadoPago</title>
<style>
:root{--bg:#0f1115;--card:#181b22;--tx:#e8e8ea;--mut:#9aa0ab;--acc:#3b82f6;--ok:#22c55e;--warn:#f59e0b;--err:#ef4444;--bd:#262a33}
*{box-sizing:border-box}body{margin:0;font-family:system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--tx)}
header{padding:18px 24px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:12px}
header h1{font-size:18px;margin:0}header .tag{font-size:12px;color:var(--mut)}
main{max-width:1100px;margin:0 auto;padding:24px;display:grid;gap:20px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:16px}
.card .n{font-size:26px;font-weight:700}.card .l{font-size:12px;color:var(--mut)}
section{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:20px}
h2{font-size:15px;margin:0 0 14px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{color:var(--mut);text-align:left;font-weight:600;padding:6px 8px;border-bottom:1px solid var(--bd)}
td{padding:8px;border-bottom:1px solid var(--bd)}
.badge{display:inline-block;padding:2px 8px;border-radius:99px;font-size:11px}
.b-ok{background:#14351f;color:var(--ok)}.b-off{background:#3a1620;color:var(--err)}.b-warn{background:#3a2b10;color:var(--warn)}.b-info{background:#12233f;color:#7fb1ff}
input,select{background:#0f1115;border:1px solid var(--bd);color:var(--tx);border-radius:8px;padding:9px 10px;font-size:13px;width:100%}
label{font-size:12px;color:var(--mut);display:block;margin:10px 0 4px}
button{background:var(--acc);border:0;color:#fff;border-radius:8px;padding:10px 16px;font-size:13px;cursor:pointer}
button.sec{background:transparent;border:1px solid var(--bd);color:var(--mut)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.note{font-size:12px;color:var(--mut);margin-top:10px;line-height:1.5}
.warnbar{background:#3a2b10;color:var(--warn);padding:10px 14px;border-radius:8px;font-size:13px;display:none}
@media(max-width:700px){.grid2{grid-template-columns:1fr}}
</style></head><body>
<header><h1>☕ Panel Jetinno + MercadoPago</h1><span class="tag">multi-cliente</span></header>
<main>
<div id="warnDb" class="warnbar">⚠️ Sin base de datos conectada: los clientes que agregues se pierden al reiniciar. Configurá DATABASE_URL para persistencia.</div>
<div class="cards">
  <div class="card"><div class="n" id="stClients">–</div><div class="l">Clientes</div></div>
  <div class="card"><div class="n" id="stMachines">–</div><div class="l">Máquinas</div></div>
  <div class="card"><div class="n" id="stOrders">–</div><div class="l">Órdenes</div></div>
  <div class="card"><div class="n" id="stDb">–</div><div class="l">Base de datos</div></div>
</div>

<section>
<h2>💰 Cobros</h2>
<div class="cards">
  <div class="card"><div class="n" id="sHoy">–</div><div class="l">Hoy <span id="sHoyN"></span></div></div>
  <div class="card"><div class="n" id="sSem">–</div><div class="l">Últimos 7 días <span id="sSemN"></span></div></div>
  <div class="card"><div class="n" id="sMes">–</div><div class="l">Este mes <span id="sMesN"></span></div></div>
  <div class="card"><div class="n" id="sTot">–</div><div class="l">Histórico <span id="sTotN"></span></div></div>
</div>
<div id="chart" style="display:flex;align-items:flex-end;gap:4px;height:90px;margin-top:16px"></div>
<div class="note" id="chartLbl">Ventas por día (últimos 14 días)</div>
<div class="grid2" style="margin-top:16px">
  <div>
    <h2 style="font-size:13px">Por máquina</h2>
    <table id="tblStatM"><thead><tr><th>Máquina</th><th>Ventas</th><th>Monto</th></tr></thead><tbody></tbody></table>
  </div>
  <div>
    <h2 style="font-size:13px">Por cliente</h2>
    <table id="tblStatC"><thead><tr><th>Cliente</th><th>Ventas</th><th>Monto</th></tr></thead><tbody></tbody></table>
  </div>
</div>
<div class="note" id="sReem"></div>
<div class="note">Nota: montos brutos cobrados por QR (no descuentan comisiones ni retenciones de MercadoPago).</div>
</section>

<section>
<h2>Clientes</h2>
<table id="tblClients"><thead><tr><th>Nombre</th><th>Username Jetinno</th><th>MP User ID</th><th>MercadoPago</th><th>Estado</th><th></th></tr></thead><tbody></tbody></table>
<div class="note">Un cliente = un nombre identificador + su cuenta de MercadoPago. La apikey de Jetinno solo hace falta para cuentas nivel 1 (como AR1362); los clientes ruteados por máquina no la necesitan. Sin token de MP, sus QR salen en modo simulación.</div>
</section>

<section>
<h2>Agregar / actualizar cliente</h2>
<div class="grid2">
  <div><label>Nombre del cliente</label><input id="fName" placeholder="Ej: Café López SRL"></div>
  <div><label>Username Jetinno (cuenta IOT)</label><input id="fUser" placeholder="Ej: AR9999"></div>
  <div><label>Apikey Jetinno (opcional — solo cuentas nivel 1)</label><input id="fKey" placeholder="Dejar vacío para clientes por máquina"></div>
  <div><label>MP User ID (número al final del token)</label><input id="fMpId" placeholder="Ej: 2980081299"></div>
  <div style="grid-column:1/-1"><label>Access Token de MercadoPago del cliente</label><input id="fMpTok" placeholder="APP_USR-..." type="password"></div>
</div>
<div style="margin-top:14px;display:flex;gap:10px;align-items:center">
  <button onclick="saveClient()">Guardar cliente</button><span id="saveMsg" class="note"></span>
</div>
<div class="note">Para actualizar un cliente existente, usá el mismo username: los campos vacíos de MP no pisan los guardados.</div>
</section>

<section>
<h2>Máquinas — ⚠️ acá se decide a qué MercadoPago va la plata de cada equipo</h2>
<div class="note">Al asignar una máquina a un cliente, sus cobros van al MercadoPago de ESE cliente. Las máquinas sin asignar cobran en el MercadoPago de la cuenta principal.</div>
<table id="tblMachines"><thead><tr><th>N° máquina</th><th>Cliente</th><th>Etiqueta</th><th></th></tr></thead><tbody></tbody></table>
<div class="grid2" style="margin-top:12px">
  <div><label>N° de máquina (vmc_no)</label><input id="mDev" placeholder="Ej: 173840"></div>
  <div><label>Username del cliente</label><input id="mUser" placeholder="Ej: AR1362"></div>
  <div style="grid-column:1/-1"><label>Etiqueta / ubicación</label><input id="mLabel" placeholder="Ej: Alberti 55 - hall"></div>
</div>
<div style="margin-top:12px"><button onclick="saveMachine()">Registrar máquina</button> <span id="mMsg" class="note"></span></div>
</section>

<section>
<h2>Últimas órdenes</h2>
<table id="tblOrders"><thead><tr><th>Fecha</th><th>Orden</th><th>Cliente</th><th>Máquina</th><th>Producto</th><th>Monto</th><th>Estado</th></tr></thead><tbody></tbody></table>
</section>

<section>
<h2>Datos para dar de alta un cliente en Jetinno</h2>
<div class="note">Cuando Jetinno cree la cuenta IOT del cliente, pasales estas URLs (las mismas para todos los clientes):<br><br>
qRUrl: <b id="uQr"></b><br>scanUrl: <b id="uScan"></b><br>refundUrl: <b id="uRef"></b></div>
</section>
</main>
<script>
const api=(p,opt)=>fetch('/admin/api/'+p,opt).then(r=>r.json());
const money=c=>'$'+(c/100).toFixed(2);
const esc=s=>String(s??'').replace(/[&<>"]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[m]));
async function refreshStats(){
  const s=await api('stats');
  if(s.error) return;
  sHoy.textContent=money(s.hoy.cents); sHoyN.textContent='('+s.hoy.n+' ventas)';
  sSem.textContent=money(s.semana.cents); sSemN.textContent='('+s.semana.n+')';
  sMes.textContent=money(s.mes.cents); sMesN.textContent='('+s.mes.n+')';
  sTot.textContent=money(s.total.cents); sTotN.textContent='('+s.total.n+')';
  sReem.textContent=s.reembolsos.n?('Reembolsos: '+s.reembolsos.n+' por '+money(s.reembolsos.cents)):'';
  tblStatM.tBodies[0].innerHTML=s.porMaquina.map(m=>'<tr><td><b>'+esc(m.device)+'</b></td><td>'+m.n+'</td><td>'+money(m.cents)+'</td></tr>').join('')||'<tr><td colspan=3 style="color:var(--mut)">Sin ventas aún</td></tr>';
  tblStatC.tBodies[0].innerHTML=s.porCliente.map(c=>'<tr><td><b>'+esc(c.username)+'</b></td><td>'+c.n+'</td><td>'+money(c.cents)+'</td></tr>').join('')||'<tr><td colspan=3 style="color:var(--mut)">Sin ventas aún</td></tr>';
  const days=[...Array(14)].map((_,i)=>{const d=new Date(Date.now()-(13-i)*864e5);return d.toISOString().slice(0,10);});
  const map={}; (s.porDia||[]).forEach(r=>{map[String(r.dia).slice(0,10)]=r.cents;});
  const max=Math.max(1,...days.map(d=>map[d]||0));
  chart.innerHTML=days.map(d=>{const v=map[d]||0;const h=Math.max(3,Math.round(v/max*82));
    return '<div title="'+d+': '+money(v)+'" style="flex:1;background:'+(v?'var(--acc)':'var(--bd)')+';height:'+h+'px;border-radius:3px 3px 0 0"></div>';}).join('');
}
async function refresh(){
  refreshStats();
  const st=await api('status');
  stClients.textContent=st.clients; stMachines.textContent=st.machines; stOrders.textContent=st.orders;
  stDb.textContent=st.db?'✔':'✖'; warnDb.style.display=st.db?'none':'block';
  const base=location.origin; uQr.textContent=base+'/getQrCode'; uScan.textContent=base+'/payBarCode'; uRef.textContent=base+'/refund';
  const cs=await api('clients');
  tblClients.tBodies[0].innerHTML=cs.map(c=>'<tr><td>'+esc(c.name)+'</td><td><b>'+esc(c.username)+'</b></td><td>'+esc(c.mpUserId||'—')+'</td>'+
    '<td>'+(c.hasMp?'<span class="badge b-ok">conectado</span>':'<span class="badge b-warn">simulación</span>')+'</td>'+
    '<td>'+(c.active?'<span class="badge b-ok">activo</span>':'<span class="badge b-off">pausado</span>')+'</td>'+
    '<td><button class="sec" onclick="toggleC(\\''+esc(c.username)+'\\')">'+(c.active?'Pausar':'Activar')+'</button></td></tr>').join('');
  const ms=await api('machines');
  tblMachines.tBodies[0].innerHTML=ms.map(m=>'<tr><td><b>'+esc(m.device_no)+'</b></td><td>'+esc(m.client_name||m.username||'—')+'</td><td>'+esc(m.label||'')+'</td>'+
    '<td><button class="sec" onclick="delM('+m.id+')">Quitar</button></td></tr>').join('')||'<tr><td colspan=4 style="color:var(--mut)">Sin máquinas registradas</td></tr>';
  const os=await api('orders');
  tblOrders.tBodies[0].innerHTML=os.map(o=>{
    const b={PAID:'b-ok',DELIVERED:'b-ok',PENDING:'b-info',PAYING:'b-info',REFUNDED:'b-warn'}[o.status]||'b-off';
    const dt=o.created_at?new Date(o.created_at).toLocaleString('es-AR'):'—';
    return '<tr><td>'+dt+'</td><td style="font-family:monospace;font-size:11px">'+esc(o.order_no)+'</td><td>'+esc(o.client_username||'')+'</td><td>'+esc(o.device_no||'')+'</td><td>'+esc(o.product||'')+'</td><td>'+money(o.amount_cents||0)+'</td><td><span class="badge '+b+'">'+esc(o.status)+'</span></td></tr>';
  }).join('')||'<tr><td colspan=7 style="color:var(--mut)">Sin órdenes todavía</td></tr>';
}
async function saveClient(){
  saveMsg.textContent='Guardando...';
  const r=await api('clients',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:fName.value,username:fUser.value.trim(),apikey:fKey.value.trim(),mpUserId:fMpId.value.trim(),mpToken:fMpTok.value.trim()})});
  saveMsg.textContent=r.ok?('✔ Guardado.'+(r.warning?' '+r.warning:'')):('✖ '+(r.error||'error'));
  if(r.ok){fName.value=fUser.value=fKey.value=fMpId.value=fMpTok.value='';}
  refresh();
}
async function toggleC(u){await api('clients/'+encodeURIComponent(u)+'/toggle',{method:'POST'});refresh();}
async function saveMachine(){
  const r=await api('machines',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({deviceNo:mDev.value.trim(),username:mUser.value.trim(),label:mLabel.value})});
  mMsg.textContent=r.ok?'✔ Registrada':'✖ '+(r.error||'error');
  if(r.ok){mDev.value=mUser.value=mLabel.value='';}
  refresh();
}
async function delM(id){await api('machines/'+id+'/delete',{method:'POST'});refresh();}
refresh();setInterval(refresh,30000);
</script></body></html>`);
});

// ================= Arranque =================
initDb().finally(() => {
  app.listen(PORT, () => console.log(`Bridge multi-cliente escuchando en :${PORT} (db=${dbReady})`));
});
