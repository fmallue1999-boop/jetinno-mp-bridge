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
    await pool.query(`ALTER TABLE clients ADD COLUMN IF NOT EXISTS portal_key TEXT DEFAULT ''`).catch(() => {});
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

// ============ Portal de clientes (acceso por link secreto) ============
async function ensurePortalKey(username) {
  if (!dbReady) return '';
  const r = await pool.query('SELECT portal_key FROM clients WHERE jetinno_username=$1', [username]);
  if (!r.rows.length) return '';
  let key = r.rows[0].portal_key;
  if (!key) {
    key = crypto.randomBytes(9).toString('hex'); // 18 chars
    await pool.query('UPDATE clients SET portal_key=$2 WHERE jetinno_username=$1', [username, key]);
  }
  return key;
}
async function getClientByPortalKey(key) {
  if (!dbReady || !key || String(key).length < 10) return null;
  const r = await pool.query('SELECT name, jetinno_username FROM clients WHERE portal_key=$1 AND active=TRUE', [String(key)]);
  return r.rows.length ? r.rows[0] : null;
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

// ================= PORTAL DE CLIENTES =================
app.get('/portal/api/summary', async (req, res) => {
  try {
    const cli = await getClientByPortalKey(req.query.k);
    if (!cli) return res.status(404).json({ error: 'link inválido' });
    const u = cli.jetinno_username;
    const owner = `COALESCE(NULLIF(mp_username,''), client_username)`;
    const paid = `status IN ('PAID','DELIVERED')`;
    const localDate = `(created_at AT TIME ZONE '${TZ}')::date`;
    const todayLocal = `(now() AT TIME ZONE '${TZ}')::date`;
    const q = async (sql, params) => (await pool.query(sql, params)).rows;
    const [hoy] = await q(`SELECT COUNT(*) n, COALESCE(SUM(amount_cents),0) c FROM orders WHERE ${paid} AND ${owner}=$1 AND ${localDate}=${todayLocal}`, [u]);
    const [semana] = await q(`SELECT COUNT(*) n, COALESCE(SUM(amount_cents),0) c FROM orders WHERE ${paid} AND ${owner}=$1 AND created_at >= now() - interval '7 days'`, [u]);
    const [mes] = await q(`SELECT COUNT(*) n, COALESCE(SUM(amount_cents),0) c FROM orders WHERE ${paid} AND ${owner}=$1 AND date_trunc('month', created_at AT TIME ZONE '${TZ}') = date_trunc('month', now() AT TIME ZONE '${TZ}')`, [u]);
    const [total] = await q(`SELECT COUNT(*) n, COALESCE(SUM(amount_cents),0) c FROM orders WHERE ${paid} AND ${owner}=$1`, [u]);
    const porDia = await q(`SELECT ${localDate} d, COALESCE(SUM(amount_cents),0) c FROM orders WHERE ${paid} AND ${owner}=$1 AND created_at >= now() - interval '14 days' GROUP BY 1 ORDER BY 1`, [u]);
    const porMaquina = await q(`SELECT device_no, COUNT(*) n, COALESCE(SUM(amount_cents),0) c FROM orders WHERE ${paid} AND ${owner}=$1 GROUP BY device_no ORDER BY c DESC`, [u]);
    const maquinas = await q(`SELECT m.device_no, m.label FROM machines m JOIN clients c ON c.id=m.client_id WHERE c.jetinno_username=$1 ORDER BY m.device_no`, [u]);
    const orders = await q(`SELECT order_no, device_no, amount_cents, product, status, created_at FROM orders WHERE ${owner}=$1 ORDER BY created_at DESC LIMIT 50`, [u]);
    res.json({
      name: cli.name,
      hoy: { n: +hoy.n, cents: +hoy.c }, semana: { n: +semana.n, cents: +semana.c },
      mes: { n: +mes.n, cents: +mes.c }, total: { n: +total.n, cents: +total.c },
      porDia: porDia.map((r) => ({ dia: r.d, cents: +r.c })),
      porMaquina: porMaquina.map((r) => ({ device: r.device_no, n: +r.n, cents: +r.c })),
      maquinas, orders,
    });
  } catch (e) { console.error('[portal]', e.message); res.status(500).json({ error: 'error' }); }
});

app.get('/portal', async (req, res) => {
  const cli = await getClientByPortalKey(req.query.k).catch(() => null);
  if (!cli) return res.status(404).type('html').send('<body style="font-family:sans-serif;background:#0b0d12;color:#e9ecf2;display:grid;place-items:center;height:100vh;margin:0"><div style="text-align:center"><h2>Link inválido o vencido</h2><p style="color:#8b93a3">Pedile un link nuevo a tu proveedor.</p></div></body>');
  res.type('html').send(`<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Panel de ventas</title>
<style>
:root{--bg:#0b0d12;--card:#151922;--tx:#e9ecf2;--mut:#8b93a3;--acc:#4f8cff;--ok:#2ecc71;--warn:#f5a623;--err:#ff5c5c;--bd:#252c3b}
*{box-sizing:border-box}body{margin:0;font-family:Inter,system-ui,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--tx);font-size:14px}
header{padding:22px;text-align:center;border-bottom:1px solid var(--bd)}
header .t{font-size:19px;font-weight:800}header .s{color:var(--mut);font-size:12.5px;margin-top:4px}
main{max-width:920px;margin:0 auto;padding:22px 18px 60px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:16px}
.kpi .l{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.6px}
.kpi .v{font-size:22px;font-weight:800;margin-top:3px}
.kpi .s{font-size:12px;color:var(--mut);margin-top:3px}
h2{font-size:14px;margin:0 0 12px}
.sect{margin-top:18px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{color:var(--mut);text-align:left;font-weight:600;padding:7px 9px;border-bottom:1px solid var(--bd);font-size:11px;text-transform:uppercase}
td{padding:9px;border-bottom:1px solid var(--bd)}
.badge{display:inline-block;padding:2px 9px;border-radius:99px;font-size:11px;font-weight:600}
.b-ok{background:rgba(46,204,113,.13);color:var(--ok)}.b-info{background:rgba(79,140,255,.13);color:#8ab4ff}
.b-warn{background:rgba(245,166,35,.13);color:var(--warn)}.b-err{background:rgba(255,92,92,.13);color:var(--err)}
#chart{display:flex;align-items:flex-end;gap:4px;height:90px;margin-top:6px}
#chart .bar{flex:1;border-radius:3px 3px 0 0;background:var(--acc);min-height:3px}
#chart .bar.z{background:var(--bd)}
.note{font-size:12px;color:var(--mut);text-align:center;margin-top:24px}
</style></head><body>
<header><div class="t" id="cName">Panel de ventas</div><div class="s">Ventas con QR de MercadoPago · se actualiza solo</div></header>
<main>
<div class="grid">
  <div class="card kpi"><div class="l">Hoy</div><div class="v" id="kHoy">–</div><div class="s" id="kHoyN"></div></div>
  <div class="card kpi"><div class="l">7 días</div><div class="v" id="kSem">–</div><div class="s" id="kSemN"></div></div>
  <div class="card kpi"><div class="l">Este mes</div><div class="v" id="kMes">–</div><div class="s" id="kMesN"></div></div>
  <div class="card kpi"><div class="l">Histórico</div><div class="v" id="kTot">–</div><div class="s" id="kTotN"></div></div>
</div>
<div class="card sect"><h2>Ventas por día — últimos 14 días</h2><div id="chart"></div></div>
<div class="card sect"><h2>Tus máquinas</h2><table><thead><tr><th>Máquina</th><th>Ubicación</th><th>Ventas</th><th>Monto</th></tr></thead><tbody id="tbM"></tbody></table></div>
<div class="card sect"><h2>Últimas ventas</h2><table><thead><tr><th>Fecha</th><th>Máquina</th><th>Producto</th><th>Monto</th><th>Estado</th></tr></thead><tbody id="tbO"></tbody></table></div>
<div class="note">Los montos son brutos (no descuentan comisiones de MercadoPago).<br>Panel provisto por tu proveedor de máquinas.</div>
</main>
<script>
var K=new URLSearchParams(location.search).get('k');
var $=function(i){return document.getElementById(i)};
var money=function(c){return '$'+((c||0)/100).toLocaleString('es-AR',{minimumFractionDigits:2,maximumFractionDigits:2})};
var esc=function(s){return String(s==null?'':s).replace(/[&<>"']/g,function(m){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]})};
function load(){
  fetch('/portal/api/summary?k='+encodeURIComponent(K)).then(function(r){return r.json()}).then(function(d){
    if(d.error)return;
    $('cName').textContent=d.name;
    document.title=d.name+' — Ventas';
    $('kHoy').textContent=money(d.hoy.cents);$('kHoyN').textContent=d.hoy.n+' ventas';
    $('kSem').textContent=money(d.semana.cents);$('kSemN').textContent=d.semana.n+' ventas';
    $('kMes').textContent=money(d.mes.cents);$('kMesN').textContent=d.mes.n+' ventas';
    $('kTot').textContent=money(d.total.cents);$('kTotN').textContent=d.total.n+' ventas';
    var days=[],i;for(i=13;i>=0;i--){days.push(new Date(Date.now()-i*864e5).toISOString().slice(0,10))}
    var map={};(d.porDia||[]).forEach(function(r){map[String(r.dia).slice(0,10)]=r.cents});
    var max=Math.max.apply(null,[1].concat(days.map(function(x){return map[x]||0})));
    $('chart').innerHTML=days.map(function(x){var v=map[x]||0;var h=Math.max(3,Math.round(v/max*82));
      return '<div class="bar'+(v?'':' z')+'" style="height:'+h+'px" title="'+x+': '+money(v)+'"></div>'}).join('');
    var labels={};(d.maquinas||[]).forEach(function(m){labels[m.device_no]=m.label});
    $('tbM').innerHTML=(d.porMaquina||[]).map(function(m){
      return '<tr><td><b>'+esc(m.device)+'</b></td><td>'+esc(labels[m.device]||'—')+'</td><td>'+m.n+'</td><td>'+money(m.cents)+'</td></tr>'}).join('')||'<tr><td colspan=4 style="color:var(--mut)">Sin ventas aún</td></tr>';
    $('tbO').innerHTML=(d.orders||[]).map(function(o){
      var b={PAID:'b-ok',DELIVERED:'b-ok',PENDING:'b-info',PAYING:'b-info',REFUNDED:'b-warn'}[o.status]||'b-err';
      var dt=o.created_at?new Date(o.created_at).toLocaleString('es-AR',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'}):'—';
      return '<tr><td>'+dt+'</td><td>'+esc(o.device_no||'')+'</td><td>'+esc(o.product||'')+'</td><td><b>'+money(o.amount_cents)+'</b></td><td><span class="badge '+b+'">'+esc(o.status)+'</span></td></tr>'}).join('')||'<tr><td colspan=5 style="color:var(--mut)">Sin ventas aún</td></tr>';
  });
}
load();setInterval(load,60000);
</script></body></html>`);
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
    const r = await pool.query('SELECT id,name,jetinno_username,mp_user_id,active,portal_key, (mp_token_enc<>\'\') AS has_mp, (jetinno_apikey_enc<>\'\') AS has_key FROM clients ORDER BY id');
    for (const c of r.rows) {
      const pk = c.portal_key || await ensurePortalKey(c.jetinno_username);
      out.push({ id: c.id, name: c.name, username: c.jetinno_username, mpUserId: c.mp_user_id, hasMp: c.has_mp, hasKey: c.has_key, active: c.active, portalKey: pk });
    }
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

// Diagnóstico: ¿a qué cuenta de MercadoPago pertenece el token guardado de un cliente?
app.get('/admin/api/whoami', adminAuth, async (req, res) => {
  try {
    const client = await getClient(req.query.u);
    if (!client) return res.status(404).json({ error: 'cliente no encontrado' });
    if (!client.mp_token) return res.json({ cliente: client.jetinno_username, mp: 'sin token (simulación)' });
    const me = await mpFetch(client, '/users/me');
    res.json({
      cliente: client.jetinno_username,
      tokenPerteneceA: { id: me.id, nombre: `${me.first_name || ''} ${me.last_name || ''}`.trim(), nickname: me.nickname, tipo: me.site_status || '' },
      mpUserIdCargado: client.mp_user_id,
      coincide: String(me.id) === String(client.mp_user_id),
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/admin/api/orders', adminAuth, async (_req, res) => {
  if (dbReady) {
    const r = await pool.query('SELECT order_no, client_username, mp_username, device_no, amount_cents, product, status, mp_payment_id, created_at FROM orders ORDER BY created_at DESC LIMIT 100');
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
<title>Jetinno · MercadoPago — Panel</title>
<style>
:root{--bg:#0b0d12;--card:#151922;--card2:#1b2130;--tx:#e9ecf2;--mut:#8b93a3;--acc:#4f8cff;--acc2:#3465c9;--ok:#2ecc71;--warn:#f5a623;--err:#ff5c5c;--bd:#252c3b;--r:14px}
*{box-sizing:border-box}body{margin:0;font-family:Inter,system-ui,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--tx);font-size:14px}
.topbar{position:sticky;top:0;z-index:50;background:rgba(11,13,18,.92);backdrop-filter:blur(8px);border-bottom:1px solid var(--bd)}
.topin{max-width:1180px;margin:0 auto;padding:14px 22px;display:flex;align-items:center;gap:18px;flex-wrap:wrap}
.brand{font-weight:800;font-size:16px;letter-spacing:.2px;display:flex;align-items:center;gap:8px}
.brand .dot{width:9px;height:9px;border-radius:50%;background:var(--err)}
.brand .dot.on{background:var(--ok);box-shadow:0 0 8px var(--ok)}
.tabs{display:flex;gap:4px;background:var(--card);padding:4px;border-radius:12px;border:1px solid var(--bd)}
.tab{border:0;background:transparent;color:var(--mut);padding:8px 16px;border-radius:9px;cursor:pointer;font-size:13.5px;font-weight:600;transition:.15s}
.tab:hover{color:var(--tx)}
.tab.active{background:var(--acc);color:#fff;box-shadow:0 2px 10px rgba(79,140,255,.35)}
.spacer{flex:1}
.rbtn{border:1px solid var(--bd);background:var(--card);color:var(--mut);border-radius:9px;padding:8px 13px;cursor:pointer}
.rbtn:hover{color:var(--tx)}
main{max-width:1180px;margin:0 auto;padding:24px 22px 60px}
.pane{display:none}.pane.active{display:block;animation:fade .18s ease}
@keyframes fade{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
.grid4{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:var(--r);padding:18px}
.kpi .v{font-size:26px;font-weight:800;margin-top:2px}
.kpi .l{font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.6px}
.kpi .s{font-size:12px;color:var(--mut);margin-top:4px}
h2{font-size:15px;margin:0 0 14px;font-weight:700}
.sect{margin-top:22px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{color:var(--mut);text-align:left;font-weight:600;padding:8px 10px;border-bottom:1px solid var(--bd);font-size:11.5px;text-transform:uppercase;letter-spacing:.5px}
td{padding:10px;border-bottom:1px solid var(--bd)}
tbody tr:hover{background:rgba(79,140,255,.05)}
.badge{display:inline-block;padding:3px 10px;border-radius:99px;font-size:11px;font-weight:600}
.b-ok{background:rgba(46,204,113,.13);color:var(--ok)}.b-err{background:rgba(255,92,92,.13);color:var(--err)}
.b-warn{background:rgba(245,166,35,.13);color:var(--warn)}.b-info{background:rgba(79,140,255,.13);color:#8ab4ff}
input,select{background:#0e1117;border:1px solid var(--bd);color:var(--tx);border-radius:10px;padding:10px 12px;font-size:13.5px;width:100%;outline:0;transition:.15s}
input:focus,select:focus{border-color:var(--acc)}
label{font-size:11.5px;color:var(--mut);display:block;margin:12px 0 5px;text-transform:uppercase;letter-spacing:.5px;font-weight:600}
button.pri{background:var(--acc);border:0;color:#fff;border-radius:10px;padding:11px 20px;font-size:13.5px;font-weight:700;cursor:pointer;transition:.15s}
button.pri:hover{background:var(--acc2)}
button.sec{background:transparent;border:1px solid var(--bd);color:var(--mut);border-radius:9px;padding:7px 13px;font-size:12.5px;cursor:pointer}
button.sec:hover{color:var(--tx);border-color:var(--mut)}
button.dng{background:transparent;border:1px solid rgba(255,92,92,.4);color:var(--err);border-radius:9px;padding:7px 13px;font-size:12.5px;cursor:pointer}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px}
@media(max-width:760px){.grid2,.grid3{grid-template-columns:1fr}}
.note{font-size:12.5px;color:var(--mut);line-height:1.6}
.hint{background:rgba(245,166,35,.08);border:1px solid rgba(245,166,35,.25);border-radius:12px;padding:12px 16px;font-size:12.5px;color:#e8c583;margin-bottom:16px}
details.grp{background:var(--card);border:1px solid var(--bd);border-radius:var(--r);margin-bottom:12px;overflow:hidden}
details.grp summary{cursor:pointer;padding:15px 18px;font-weight:700;display:flex;align-items:center;gap:10px;list-style:none;user-select:none}
details.grp summary::-webkit-details-marker{display:none}
details.grp summary .chev{transition:.2s;color:var(--mut)}
details.grp[open] summary .chev{transform:rotate(90deg)}
details.grp summary .cnt{color:var(--mut);font-weight:500;font-size:12.5px}
details.grp .inner{padding:0 18px 14px}
#chart{display:flex;align-items:flex-end;gap:5px;height:110px;margin-top:6px}
#chart .bar{flex:1;border-radius:4px 4px 0 0;background:var(--acc);min-height:3px;position:relative;transition:.15s}
#chart .bar.z{background:var(--bd)}
#chart .bar:hover{filter:brightness(1.3)}
.toast{position:fixed;bottom:24px;right:24px;background:var(--card2);border:1px solid var(--bd);border-left:4px solid var(--ok);border-radius:12px;padding:14px 20px;font-size:13.5px;box-shadow:0 8px 30px rgba(0,0,0,.5);opacity:0;transform:translateY(10px);transition:.25s;z-index:99;max-width:340px}
.toast.show{opacity:1;transform:none}
.toast.err{border-left-color:var(--err)}
.codebox{font-family:Consolas,monospace;font-size:12px;color:#9ab8ff;background:#0e1117;border:1px solid var(--bd);border-radius:8px;padding:10px 12px;margin-top:6px;word-break:break-all}
.formcard{display:none}.formcard.open{display:block;animation:fade .18s ease}
.thead-actions{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;flex-wrap:wrap;gap:10px}
.filters{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}
.filters select,.filters input{width:auto;min-width:150px}
</style></head><body>
<div class="topbar"><div class="topin">
  <div class="brand"><span class="dot" id="dbDot"></span> ☕ Jetinno · MercadoPago</div>
  <div class="tabs">
    <button class="tab active" data-tab="dash">📊 Dashboard</button>
    <button class="tab" data-tab="cli">👥 Clientes</button>
    <button class="tab" data-tab="maq">🖥 Máquinas</button>
    <button class="tab" data-tab="ord">🧾 Órdenes</button>
  </div>
  <div class="spacer"></div>
  <button class="rbtn" id="btnRefresh">⟳ Actualizar</button>
</div></div>
<main>

<div class="pane active" id="pane-dash">
  <div class="grid4">
    <div class="card kpi"><div class="l">Hoy</div><div class="v" id="kHoy">–</div><div class="s" id="kHoyN"></div></div>
    <div class="card kpi"><div class="l">Últimos 7 días</div><div class="v" id="kSem">–</div><div class="s" id="kSemN"></div></div>
    <div class="card kpi"><div class="l">Este mes</div><div class="v" id="kMes">–</div><div class="s" id="kMesN"></div></div>
    <div class="card kpi"><div class="l">Histórico</div><div class="v" id="kTot">–</div><div class="s" id="kTotN"></div></div>
  </div>
  <div class="sect card">
    <h2>Ventas por día — últimos 14 días</h2>
    <div id="chart"></div>
  </div>
  <div class="sect grid2">
    <div class="card"><h2>Por máquina</h2><table><thead><tr><th>Máquina</th><th>Ventas</th><th>Monto</th></tr></thead><tbody id="tbM"></tbody></table></div>
    <div class="card"><h2>Por cliente</h2><table><thead><tr><th>Cliente</th><th>Ventas</th><th>Monto</th></tr></thead><tbody id="tbC"></tbody></table></div>
  </div>
  <div class="sect grid4">
    <div class="card kpi"><div class="l">Clientes</div><div class="v" id="kCli">–</div></div>
    <div class="card kpi"><div class="l">Máquinas</div><div class="v" id="kMaq">–</div></div>
    <div class="card kpi"><div class="l">Órdenes</div><div class="v" id="kOrd">–</div></div>
    <div class="card kpi"><div class="l">Reembolsos</div><div class="v" id="kReem">–</div><div class="s" id="kReemN"></div></div>
  </div>
</div>

<div class="pane" id="pane-cli">
  <div class="thead-actions"><h2 style="margin:0">Clientes</h2><button class="pri" id="btnNewCli">＋ Nuevo cliente</button></div>
  <div class="card formcard" id="cliForm">
    <h2 id="cliFormTitle">Nuevo cliente</h2>
    <div class="grid2">
      <div><label>Nombre</label><input id="fName" placeholder="Ej: Café López SRL"></div>
      <div><label>Username / identificador</label><input id="fUser" placeholder="Ej: LaFonteMaster"></div>
      <div><label>Apikey Jetinno (solo cuentas nivel 1)</label><input id="fKey" placeholder="Vacío para clientes por máquina"></div>
      <div><label>MP User ID (número final del token)</label><input id="fMpId" placeholder="Ej: 2980081299"></div>
    </div>
    <label>Access Token de MercadoPago del cliente</label><input id="fMpTok" type="password" placeholder="APP_USR-...">
    <div style="margin-top:16px;display:flex;gap:10px">
      <button class="pri" id="btnSaveCli">Guardar</button>
      <button class="sec" id="btnCancelCli">Cancelar</button>
    </div>
    <div class="note" style="margin-top:10px">Para actualizar un cliente existente usá el mismo username: los campos vacíos no pisan lo guardado.</div>
  </div>
  <div class="card" style="margin-top:14px">
    <table><thead><tr><th>Nombre</th><th>Username</th><th>MP User ID</th><th>MercadoPago</th><th>Estado</th><th style="text-align:right">Acciones</th></tr></thead><tbody id="tbCli"></tbody></table>
  </div>
  <div class="card sect">
    <h2>Datos para alta en Jetinno (siempre los mismos)</h2>
    <div class="note">Si Jetinno pide las URLs de pago, son estas:</div>
    <div class="codebox" id="urlsBox"></div>
  </div>
</div>

<div class="pane" id="pane-maq">
  <div class="hint">⚠️ La asignación decide a qué MercadoPago va la plata: máquina asignada a un cliente → cobra en el MP de ese cliente. Sin asignar → cobra en el MP de la cuenta principal.</div>
  <div class="thead-actions"><h2 style="margin:0">Máquinas por cliente</h2><button class="pri" id="btnNewMaq">＋ Asignar máquina</button></div>
  <div class="card formcard" id="maqForm">
    <h2>Asignar máquina</h2>
    <div class="grid3">
      <div><label>N° de máquina (vmc_no)</label><input id="mDev" placeholder="Ej: 181370"></div>
      <div><label>Cliente</label><select id="mCli"></select></div>
      <div><label>Etiqueta / ubicación</label><input id="mLabel" placeholder="Ej: La Fonte - Jujuy"></div>
    </div>
    <div style="margin-top:16px;display:flex;gap:10px">
      <button class="pri" id="btnSaveMaq">Guardar</button>
      <button class="sec" id="btnCancelMaq">Cancelar</button>
    </div>
  </div>
  <div id="maqGroups" style="margin-top:14px"></div>
</div>

<div class="pane" id="pane-ord">
  <h2>Órdenes</h2>
  <div class="filters">
    <select id="oCli"><option value="">Todos los clientes</option></select>
    <select id="oEst"><option value="">Todos los estados</option><option>PAID</option><option>DELIVERED</option><option>PENDING</option><option>PAYING</option><option>REFUNDED</option></select>
    <input id="oBusca" placeholder="Buscar orden o máquina...">
  </div>
  <div class="card">
    <table><thead><tr><th>Fecha</th><th>Orden</th><th>Cliente (MP)</th><th>Máquina</th><th>Producto</th><th>Monto</th><th>Estado</th></tr></thead><tbody id="tbOrd"></tbody></table>
  </div>
</div>

</main>
<div class="toast" id="toast"></div>
<script>
var api=function(p,opt){return fetch('/admin/api/'+p,opt).then(function(r){return r.json()})};
var $=function(id){return document.getElementById(id)};
var esc=function(s){return String(s==null?'':s).replace(/[&<>"']/g,function(m){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]})};
var money=function(c){return '$'+((c||0)/100).toLocaleString('es-AR',{minimumFractionDigits:2,maximumFractionDigits:2})};
var D={clients:[],machines:[],orders:[],stats:null,status:null};
var toastT;
function toast(msg,err){var t=$('toast');t.textContent=msg;t.className='toast show'+(err?' err':'');clearTimeout(toastT);toastT=setTimeout(function(){t.className='toast'},3200)}

document.querySelectorAll('.tab').forEach(function(b){b.onclick=function(){
  document.querySelectorAll('.tab').forEach(function(x){x.classList.remove('active')});
  document.querySelectorAll('.pane').forEach(function(x){x.classList.remove('active')});
  b.classList.add('active');$('pane-'+b.dataset.tab).classList.add('active');
}});

function badge(txt,cls){return '<span class="badge '+cls+'">'+esc(txt)+'</span>'}

function renderDash(){
  var s=D.stats;if(!s||s.error)return;
  $('kHoy').textContent=money(s.hoy.cents);$('kHoyN').textContent=s.hoy.n+' ventas';
  $('kSem').textContent=money(s.semana.cents);$('kSemN').textContent=s.semana.n+' ventas';
  $('kMes').textContent=money(s.mes.cents);$('kMesN').textContent=s.mes.n+' ventas';
  $('kTot').textContent=money(s.total.cents);$('kTotN').textContent=s.total.n+' ventas';
  $('kReem').textContent=s.reembolsos.n;$('kReemN').textContent=money(s.reembolsos.cents);
  var st=D.status||{};$('kCli').textContent=st.clients!=null?st.clients:'–';$('kMaq').textContent=st.machines!=null?st.machines:'–';$('kOrd').textContent=st.orders!=null?st.orders:'–';
  $('dbDot').className='dot'+(st.db?' on':'');
  $('tbM').innerHTML=(s.porMaquina||[]).map(function(m){
    var mm=D.machines.find(function(x){return x.device_no===m.device});
    var lbl=mm&&mm.label?' <span style="color:var(--mut)">· '+esc(mm.label)+'</span>':'';
    return '<tr><td><b>'+esc(m.device)+'</b>'+lbl+'</td><td>'+m.n+'</td><td>'+money(m.cents)+'</td></tr>'}).join('')||'<tr><td colspan=3 class="note">Sin ventas aún</td></tr>';
  $('tbC').innerHTML=(s.porCliente||[]).map(function(c){
    var cc=D.clients.find(function(x){return x.username===c.username});
    return '<tr><td><b>'+esc(cc?cc.name:c.username)+'</b></td><td>'+c.n+'</td><td>'+money(c.cents)+'</td></tr>'}).join('')||'<tr><td colspan=3 class="note">Sin ventas aún</td></tr>';
  var days=[],i;for(i=13;i>=0;i--){var d=new Date(Date.now()-i*864e5);days.push(d.toISOString().slice(0,10))}
  var map={};(s.porDia||[]).forEach(function(r){map[String(r.dia).slice(0,10)]=r.cents});
  var max=Math.max.apply(null,[1].concat(days.map(function(d){return map[d]||0})));
  $('chart').innerHTML=days.map(function(d){var v=map[d]||0;var h=Math.max(3,Math.round(v/max*100));
    return '<div class="bar'+(v?'':' z')+'" style="height:'+h+'px" title="'+d+': '+money(v)+'"></div>'}).join('');
}

function renderClients(){
  $('tbCli').innerHTML=D.clients.map(function(c){
    return '<tr><td><b>'+esc(c.name)+'</b></td><td>'+esc(c.username)+'</td><td>'+esc(c.mpUserId||'—')+'</td>'+
    '<td>'+(c.hasMp?badge('conectado','b-ok'):badge('simulación','b-warn'))+'</td>'+
    '<td>'+(c.active?badge('activo','b-ok'):badge('pausado','b-err'))+'</td>'+
    '<td style="text-align:right">'+(c.portalKey?'<button class="sec" data-act="portal" data-k="'+esc(c.portalKey)+'">Portal 🔗</button> ':'')+
    '<button class="sec" data-act="edit" data-u="'+esc(c.username)+'">Editar</button> '+
    '<button class="'+(c.active?'dng':'sec')+'" data-act="toggle" data-u="'+esc(c.username)+'">'+(c.active?'Pausar':'Activar')+'</button></td></tr>'}).join('')||'<tr><td colspan=6 class="note">Sin clientes</td></tr>';
  $('urlsBox').innerHTML='qRUrl: '+location.origin+'/getQrCode<br>scanUrl: '+location.origin+'/payBarCode<br>refundUrl: '+location.origin+'/refund';
}

function renderMachines(){
  var sel=$('mCli');var cur=sel.value;
  sel.innerHTML=D.clients.map(function(c){return '<option value="'+esc(c.username)+'">'+esc(c.name)+' ('+esc(c.username)+')</option>'}).join('');
  if(cur)sel.value=cur;
  var groups={};
  D.machines.forEach(function(m){var k=m.username||'(sin cliente)';(groups[k]=groups[k]||[]).push(m)});
  var html=Object.keys(groups).map(function(u){
    var cc=D.clients.find(function(x){return x.username===u});
    var name=cc?cc.name:u;
    var rows=groups[u].map(function(m){
      return '<tr><td><b>'+esc(m.device_no)+'</b></td><td>'+esc(m.label||'—')+'</td>'+
      '<td style="text-align:right"><button class="dng" data-act="delmaq" data-id="'+m.id+'">Quitar</button></td></tr>'}).join('');
    return '<details class="grp" open><summary><span class="chev">▶</span> '+esc(name)+' <span class="cnt">· '+groups[u].length+' máquina'+(groups[u].length>1?'s':'')+'</span></summary>'+
    '<div class="inner"><table><thead><tr><th>N° máquina</th><th>Etiqueta</th><th></th></tr></thead><tbody>'+rows+'</tbody></table></div></details>'}).join('');
  $('maqGroups').innerHTML=html||'<div class="card note">Sin máquinas asignadas. Las máquinas sin asignar cobran en la cuenta principal.</div>';
}

function renderOrders(){
  var selCli=$('oCli');var cur=selCli.value;
  var owners={};D.orders.forEach(function(o){var u=o.mp_username||o.client_username;if(u)owners[u]=1});
  selCli.innerHTML='<option value="">Todos los clientes</option>'+Object.keys(owners).map(function(u){
    var cc=D.clients.find(function(x){return x.username===u});
    return '<option value="'+esc(u)+'">'+esc(cc?cc.name:u)+'</option>'}).join('');
  if(cur)selCli.value=cur;
  var fc=selCli.value,fe=$('oEst').value,fb=$('oBusca').value.toLowerCase();
  var rows=D.orders.filter(function(o){
    var owner=o.mp_username||o.client_username||'';
    if(fc&&owner!==fc)return false;
    if(fe&&o.status!==fe)return false;
    if(fb&&String(o.order_no).toLowerCase().indexOf(fb)<0&&String(o.device_no).indexOf(fb)<0)return false;
    return true;
  }).map(function(o){
    var b={PAID:'b-ok',DELIVERED:'b-ok',PENDING:'b-info',PAYING:'b-info',REFUNDED:'b-warn'}[o.status]||'b-err';
    var dt=o.created_at?new Date(o.created_at).toLocaleString('es-AR',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'}):'—';
    var owner=o.mp_username||o.client_username||'';
    var cc=D.clients.find(function(x){return x.username===owner});
    return '<tr><td>'+dt+'</td><td style="font-family:monospace;font-size:11px">'+esc(o.order_no)+'</td><td>'+esc(cc?cc.name:owner)+'</td><td>'+esc(o.device_no||'')+'</td><td>'+esc(o.product||'')+'</td><td><b>'+money(o.amount_cents)+'</b></td><td>'+badge(o.status,b)+'</td></tr>'});
  $('tbOrd').innerHTML=rows.join('')||'<tr><td colspan=7 class="note">Sin órdenes</td></tr>';
}

function renderAll(){renderDash();renderClients();renderMachines();renderOrders()}
function loadAll(){
  Promise.all([api('status'),api('stats'),api('clients'),api('machines'),api('orders')]).then(function(r){
    D.status=r[0];D.stats=r[1];D.clients=r[2];D.machines=r[3];D.orders=r[4];renderAll();
  }).catch(function(){toast('Error cargando datos',true)});
}

$('btnRefresh').onclick=function(){loadAll();toast('Actualizado')};
$('btnNewCli').onclick=function(){$('cliFormTitle').textContent='Nuevo cliente';$('cliForm').classList.toggle('open')};
$('btnCancelCli').onclick=function(){$('cliForm').classList.remove('open');['fName','fUser','fKey','fMpId','fMpTok'].forEach(function(i){$(i).value=''})};
$('btnSaveCli').onclick=function(){
  api('clients',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:$('fName').value,username:$('fUser').value.trim(),apikey:$('fKey').value.trim(),mpUserId:$('fMpId').value.trim(),mpToken:$('fMpTok').value.trim()})})
  .then(function(r){if(r.ok){toast('Cliente guardado'+(r.warning?' — '+r.warning:''));$('btnCancelCli').onclick();loadAll()}else toast(r.error||'Error',true)});
};
$('btnNewMaq').onclick=function(){$('maqForm').classList.toggle('open')};
$('btnCancelMaq').onclick=function(){$('maqForm').classList.remove('open');$('mDev').value='';$('mLabel').value=''};
$('btnSaveMaq').onclick=function(){
  api('machines',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({deviceNo:$('mDev').value.trim(),username:$('mCli').value,label:$('mLabel').value})})
  .then(function(r){if(r.ok){toast('Máquina asignada');$('btnCancelMaq').onclick();loadAll()}else toast(r.error||'Error',true)});
};
$('tbCli').addEventListener('click',function(e){
  var b=e.target.closest('button');if(!b)return;
  if(b.dataset.act==='portal'){var url=location.origin+'/portal?k='+b.dataset.k;
    if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(url).then(function(){toast('Link del portal copiado — enviáselo al cliente')})}
    else{prompt('Link del portal del cliente:',url)}
    return}
  if(b.dataset.act==='toggle'){api('clients/'+encodeURIComponent(b.dataset.u)+'/toggle',{method:'POST'}).then(function(){toast('Estado actualizado');loadAll()})}
  if(b.dataset.act==='edit'){var c=D.clients.find(function(x){return x.username===b.dataset.u});if(!c)return;
    $('cliFormTitle').textContent='Editar: '+c.name;$('fName').value=c.name;$('fUser').value=c.username;$('fMpId').value=c.mpUserId||'';
    $('cliForm').classList.add('open');window.scrollTo({top:0,behavior:'smooth'})}
});
$('maqGroups').addEventListener('click',function(e){
  var b=e.target.closest('button');if(!b||b.dataset.act!=='delmaq')return;
  if(!confirm('¿Quitar esta máquina de su cliente? Volverá a cobrar en la cuenta principal.'))return;
  api('machines/'+b.dataset.id+'/delete',{method:'POST'}).then(function(){toast('Máquina quitada');loadAll()});
});
['oCli','oEst'].forEach(function(i){$(i).onchange=renderOrders});
$('oBusca').oninput=renderOrders;
loadAll();setInterval(loadAll,30000);
</script></body></html>`);
});

// ================= Arranque =================
initDb().finally(() => {
  app.listen(PORT, () => console.log(`Bridge multi-cliente escuchando en :${PORT} (db=${dbReady})`));
});
