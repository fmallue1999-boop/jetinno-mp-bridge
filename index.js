'use strict';

/**
 * Servidor puente Jetinno <-> MercadoPago QR (un solo archivo).
 * - Implementa el manual Jetinno "IOT Payment Universal Interface" (A5).
 * - Genera QR dinámico real de MercadoPago (modelo "in-store orders").
 * - Auto-crea el local (store) y la caja (POS) en MercadoPago si no existen,
 *   usando MP_ACCESS_TOKEN + MP_USER_ID (no hay que correr comandos a mano).
 *
 * Env vars:
 *   JETINNO_USERNAME, JETINNO_APIKEY          (Jetinno)
 *   MP_ACCESS_TOKEN                           (MercadoPago, secreto)
 *   MP_USER_ID                                (id de tu cuenta MP, ej 2980081299)
 *   MP_STORE_TAG        (opcional, default "173840")
 *   MP_EXTERNAL_POS_ID  (opcional, si querés fijar la caja)
 *
 * Si MP_ACCESS_TOKEN está vacío -> MODO MOCK (QR de prueba, no cobra).
 */

const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '256kb' }));

const USERNAME = process.env.JETINNO_USERNAME || 'testname';
const APIKEY = process.env.JETINNO_APIKEY || 'DBRW17YE7FHKR72T';
const PORT = process.env.PORT || 3000;

// ----------------- Firma MD5 (manual sección 2.4) -----------------
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
function flatten(message) {
  const { data, sign: _s, ...top } = message;
  return { ...top, ...(data || {}) };
}
function verify(message, apikey, { extraSignedFields = [], optionalFields = [] } = {}) {
  const flat = flatten(message);
  for (const f of optionalFields) if (!extraSignedFields.includes(f)) delete flat[f];
  return sign(flat, apikey, message.nonce) === String(message.sign || '').toUpperCase();
}

// ----------------- MercadoPago -----------------
const MP_BASE = 'https://api.mercadopago.com';
const mpMock = () => !process.env.MP_ACCESS_TOKEN;
const MP_USER_ID = process.env.MP_USER_ID || '';
const STORE_TAG = process.env.MP_STORE_TAG || '173840';
// MercadoPago exige external_id alfanumérico (sin guiones ni guiones bajos).
const STORE_EXTERNAL_ID = `JETINNOSTORE${STORE_TAG}`;
const POS_EXTERNAL_ID = process.env.MP_EXTERNAL_POS_ID || `JETINNOPOS${STORE_TAG}`;
let cachedPos = null; // external_id de la caja, una vez asegurada

async function mpFetch(path, { method = 'GET', body } = {}) {
  const res = await fetch(`${MP_BASE}${path}`, {
    method,
    headers: { Authorization: `Bearer ${process.env.MP_ACCESS_TOKEN}`, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json; try { json = text ? JSON.parse(text) : {}; } catch { json = { raw: text }; }
  if (!res.ok) { const e = new Error(`MP ${res.status} ${path}: ${text}`); e.status = res.status; e.body = json; throw e; }
  return json;
}

async function findStoreId() {
  const r = await mpFetch(`/users/${MP_USER_ID}/stores/search`);
  const list = r.results || [];
  const found = list.find((s) => s.external_id === STORE_EXTERNAL_ID);
  return found ? found.id : null;
}
async function createStore() {
  const body = {
    name: `Jetinno ${STORE_TAG}`,
    external_id: STORE_EXTERNAL_ID,
    location: {
      street_number: '55',
      street_name: 'Alberti',
      city_name: 'CABA',
      state_name: 'Buenos Aires',
      latitude: -34.6037,
      longitude: -58.3816,
    },
  };
  const r = await mpFetch(`/users/${MP_USER_ID}/stores`, { method: 'POST', body });
  return r.id;
}
async function findPos() {
  const r = await mpFetch(`/pos?external_id=${encodeURIComponent(POS_EXTERNAL_ID)}`);
  const list = r.results || [];
  return list.find((p) => p.external_id === POS_EXTERNAL_ID) || null;
}
async function createPos(storeId) {
  const body = {
    name: `Caja Jetinno ${STORE_TAG}`,
    fixed_amount: false,
    store_id: storeId,
    external_store_id: STORE_EXTERNAL_ID,
    external_id: POS_EXTERNAL_ID,
    category: 621102,
  };
  return mpFetch('/pos', { method: 'POST', body });
}

// Asegura local + caja. Devuelve el external_id de la caja.
async function ensurePos() {
  if (cachedPos) return cachedPos;
  if (!MP_USER_ID) throw new Error('Falta MP_USER_ID');
  let pos = await findPos();
  if (!pos) {
    let storeId = await findStoreId();
    if (!storeId) storeId = await createStore();
    pos = await createPos(storeId);
    console.log(`[MP] Caja creada: ${POS_EXTERNAL_ID} (store ${storeId})`);
  } else {
    console.log(`[MP] Caja existente: ${POS_EXTERNAL_ID}`);
  }
  cachedPos = POS_EXTERNAL_ID;
  return cachedPos;
}

// Crea la orden QR y devuelve el string qr_data.
async function createQrOrder(p) {
  if (mpMock()) return { qrData: `00020101021143MOCKQR-${p.orderNo}`.slice(0, 300), mpOrderId: `mock-${p.orderNo}` };
  const posExt = await ensurePos();
  const path = `/instore/orders/qr/seller/collectors/${MP_USER_ID}/pos/${encodeURIComponent(posExt)}/orders`;
  const body = {
    external_reference: p.orderNo,
    title: p.title || `Orden ${p.orderNo}`,
    description: p.title || `Orden ${p.orderNo}`,
    notification_url: process.env.MP_NOTIFICATION_URL,
    total_amount: Number(p.amount),
    items: [{
      title: p.title || `Producto ${p.orderNo}`,
      quantity: 1,
      unit_price: Number(p.amount),
      unit_measure: 'unit',
      total_amount: Number(p.amount),
    }],
  };
  const data = await mpFetch(path, { method: 'PUT', body });
  return { qrData: (data.qr_data || '').toString(), mpOrderId: data.in_store_order_id || p.orderNo };
}

async function getPayment(id) {
  const d = await mpFetch(`/v1/payments/${id}`);
  return { status: d.status, externalReference: d.external_reference };
}
async function getMerchantOrder(id) {
  const d = await mpFetch(`/merchant_orders/${id}`);
  const approved = (d.payments || []).some((p) => p.status === 'approved');
  return { paid: d.order_status === 'paid' || approved, externalReference: d.external_reference };
}
async function refundPayment(id, amount) {
  if (mpMock()) return { status: 'approved' };
  return mpFetch(`/v1/payments/${id}/refunds`, { method: 'POST', body: amount ? { amount: Number(amount) } : {} });
}

// ----------------- Estado en memoria -----------------
const orders = new Map();
function ts() {
  const d = new Date(), p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}
function ok(res, data) {
  const body = { returnCode: 'SUCCESS', msg: 'SUCCESS', time: ts() };
  if (data) { body.data = data; body.sign = sign({ username: USERNAME, time: body.time, ...data }, APIKEY); }
  res.json(body);
}
function fail(res, msg = 'FAIL') { res.json({ returnCode: 'FAIL', msg, time: ts() }); }
function checkSign(req, res, opts) {
  if (req.body.username !== USERNAME) { fail(res, 'USER_NOT_EXIST'); return false; }
  if (!verify(req.body, APIKEY, opts)) { fail(res, 'SIGN_ERROR'); return false; }
  return true;
}

// ----------------- Endpoints Jetinno -----------------
app.post('/getQrCode', async (req, res) => {
  const d = req.body.data || {};
  console.log(`[getQrCode] pedido: device=${d.deviceNo} order=${d.orderNo} monto(cents)=${d.orderAmount} prod=${d.productId}`);
  try {
    if (!checkSign(req, res, { optionalFields: ['payType', 'merchantNo', 'attach'] })) { console.log('[getQrCode] firma/usuario rechazado'); return; }
    const amountCents = parseInt(d.orderAmount, 10);
    const { qrData, mpOrderId } = await createQrOrder({ orderNo: d.orderNo, amount: amountCents / 100, title: d.productName });
    orders.set(d.orderNo, { deviceNo: d.deviceNo, amountCents, notifyUrl: d.notifyUrl, productId: d.productId, mpOrderId, mpPaymentId: null });
    console.log(`[getQrCode] OK -> qr len=${qrData.length}`);
    ok(res, { deviceNo: d.deviceNo, orderNo: d.orderNo, qrCode: qrData });
  } catch (e) {
    console.error('[getQrCode] ERROR', e.message);
    fail(res, 'SYSTEM_ERROR');
  }
});

app.post('/payBarCode', async (req, res) => {
  try {
    if (!checkSign(req, res, { optionalFields: ['merchantNo', 'attach'] })) return;
    const d = req.body.data || {};
    orders.set(d.orderNo, { deviceNo: d.deviceNo, amountCents: parseInt(d.orderAmount, 10), notifyUrl: d.notifyUrl, productId: d.productId });
    ok(res, { deviceNo: d.deviceNo, orderNo: d.orderNo, payStatus: 'PAYING' });
  } catch (e) { console.error('[payBarCode]', e.message); fail(res, 'SYSTEM_ERROR'); }
});

app.post('/refund', async (req, res) => {
  try {
    if (!checkSign(req, res, { optionalFields: ['merchantNo', 'platBillNo', 'attach'] })) return;
    const d = req.body.data || {};
    const o = orders.get(d.orderNo);
    if (o && o.mpPaymentId) await refundPayment(o.mpPaymentId, parseInt(d.refundAmount, 10) / 100);
    ok(res, { deviceNo: d.deviceNo, orderNo: d.orderNo, refundState: 'SUCCESS' });
  } catch (e) { console.error('[refund]', e.message); ok(res, { deviceNo: req.body?.data?.deviceNo, orderNo: req.body?.data?.orderNo, refundState: 'ERROR' }); }
});

app.post('/productdone', async (req, res) => {
  try {
    if (!checkSign(req, res, { optionalFields: ['merchantNo', 'platBillNo', 'attach'] })) return;
    const d = req.body.data || {};
    if (d.isFinish === 'ERROR') {
      const o = orders.get(d.orderNo);
      if (o && o.mpPaymentId) refundPayment(o.mpPaymentId).catch((e) => console.error('refund auto', e.message));
    }
    res.json({ returnCode: 'SUCCESS', msg: 'SUCCESS', time: ts() });
  } catch (e) { console.error('[productdone]', e.message); fail(res, 'SYSTEM_ERROR'); }
});

// ----------------- Webhook MercadoPago -----------------
app.post('/mp/webhook', async (req, res) => {
  res.sendStatus(200);
  try {
    const q = req.query || {};
    const b = req.body || {};
    const type = b.type || q.type || q.topic;
    let orderNo = null, payId = null;
    if (type === 'payment') {
      payId = b.data?.id || q['data.id'] || q.id;
      if (payId) { const pay = await getPayment(payId); if (pay.status === 'approved') orderNo = pay.externalReference; }
    } else if (type === 'merchant_order') {
      const moId = b.data?.id || q.id;
      if (moId) { const mo = await getMerchantOrder(moId); if (mo.paid) orderNo = mo.externalReference; }
    }
    console.log(`[mp/webhook] type=${type} orderNo=${orderNo}`);
    if (!orderNo) return;
    const o = orders.get(orderNo);
    if (!o) return;
    if (payId) o.mpPaymentId = payId;
    await notifyJetinno(o, orderNo, 'PAYSUCCESS', payId);
    console.log(`[mp/webhook] Jetinno notificado OK ${orderNo}`);
  } catch (e) { console.error('[mp/webhook]', e.message); }
});

async function notifyJetinno(order, orderNo, payStatus, platBillNo) {
  const time = ts();
  const data = { deviceNo: order.deviceNo, orderNo, orderAmount: String(order.amountCents), payType: '1001', payStatus };
  if (platBillNo) data.platBillNo = String(platBillNo);
  const s = sign({ username: USERNAME, time, deviceNo: data.deviceNo, orderNo: data.orderNo, orderAmount: data.orderAmount, payType: data.payType, payStatus: data.payStatus }, APIKEY);
  const r = await fetch(order.notifyUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: USERNAME, time, sign: s, data }) });
  console.log(`[callback->Jetinno] ${orderNo} ${r.status} ${await r.text()}`);
}

// ----------------- Utilidad / diagnóstico -----------------
app.get('/health', (_req, res) => res.json({ ok: true, mock: mpMock() }));
app.get('/', (_req, res) => res.send('Jetinno <-> MercadoPago bridge OK'));

// Dispara/inspecciona la creación de la caja (para depurar). Devuelve JSON legible.
app.get('/setup', async (_req, res) => {
  if (mpMock()) return res.json({ mock: true, msg: 'Sin MP_ACCESS_TOKEN: modo simulación.' });
  try {
    const pos = await ensurePos();
    res.json({ ok: true, userId: MP_USER_ID, posExternalId: pos });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message, body: e.body });
  }
});

app.listen(PORT, () => console.log(`Bridge escuchando en :${PORT} (mock=${mpMock()})`));
