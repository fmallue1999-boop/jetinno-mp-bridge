'use strict';

/**
 * Servidor puente Jetinno <-> MercadoPago QR — versión de un solo archivo (para deploy fácil).
 * Implementa el manual "Jetinno IOT Payment Universal Interface" (A5).
 *
 * Endpoints que Jetinno llama:
 *   POST /getQrCode   POST /payBarCode   POST /refund   POST /productdone
 * Webhook que MercadoPago llama:
 *   POST /mp/webhook
 * Salud:
 *   GET /health
 *
 * Sin credenciales reales corre en MODO MOCK (no cobra) para poder probar el circuito.
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

// ----------------- MercadoPago (con modo mock) -----------------
const MP_BASE = 'https://api.mercadopago.com';
const mpMock = () => !process.env.MP_ACCESS_TOKEN;

async function mpFetch(path, { method = 'GET', body } = {}) {
  const res = await fetch(`${MP_BASE}${path}`, {
    method,
    headers: { Authorization: `Bearer ${process.env.MP_ACCESS_TOKEN}`, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json; try { json = text ? JSON.parse(text) : {}; } catch { json = { raw: text }; }
  if (!res.ok) { const e = new Error(`MercadoPago ${res.status}: ${text}`); e.body = json; throw e; }
  return json;
}
async function createQrOrder(p) {
  if (mpMock()) return { qrData: `00020101021143MOCKQR-${p.orderNo}`.slice(0, 128), mpOrderId: `mock-${p.orderNo}` };
  const userId = process.env.MP_USER_ID, posId = process.env.MP_EXTERNAL_POS_ID;
  if (!userId || !posId) throw new Error('Faltan MP_USER_ID y/o MP_EXTERNAL_POS_ID');
  const path = `/instore/orders/qr/seller/collectors/${userId}/pos/${posId}/orders`;
  const body = {
    external_reference: p.orderNo,
    title: p.title || `Orden ${p.orderNo}`,
    notification_url: process.env.MP_NOTIFICATION_URL,
    total_amount: Number(p.amount),
    items: [{ title: p.title || `Producto ${p.orderNo}`, quantity: 1, unit_price: Number(p.amount), unit_measure: 'unit', total_amount: Number(p.amount) }],
  };
  const data = await mpFetch(path, { method: 'PUT', body });
  return { qrData: (data.qr_data || data.in_store_order_id || '').toString().slice(0, 128), mpOrderId: data.in_store_order_id || p.orderNo };
}
async function getPayment(id) {
  if (mpMock()) return { status: 'approved', externalReference: 'mock', amount: 0 };
  const d = await mpFetch(`/v1/payments/${id}`);
  return { status: d.status, externalReference: d.external_reference, amount: d.transaction_amount };
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

// ----------------- Endpoints -----------------
app.post('/getQrCode', async (req, res) => {
  try {
    if (!checkSign(req, res, { optionalFields: ['payType', 'merchantNo', 'attach'] })) return;
    const d = req.body.data || {};
    const amountCents = parseInt(d.orderAmount, 10);
    const { qrData, mpOrderId } = await createQrOrder({ orderNo: d.orderNo, amount: amountCents / 100, title: d.productName });
    orders.set(d.orderNo, { deviceNo: d.deviceNo, amountCents, notifyUrl: d.notifyUrl, productId: d.productId, mpOrderId, mpPaymentId: null });
    ok(res, { deviceNo: d.deviceNo, orderNo: d.orderNo, qrCode: qrData });
  } catch (e) { console.error('[getQrCode]', e.message); fail(res, 'SYSTEM_ERROR'); }
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

app.post('/mp/webhook', async (req, res) => {
  res.sendStatus(200);
  try {
    const paymentId = req.body?.data?.id || req.query['data.id'];
    if (!paymentId) return;
    const pay = await getPayment(paymentId);
    if (pay.status !== 'approved') return;
    const o = orders.get(pay.externalReference);
    if (!o) return;
    o.mpPaymentId = paymentId;
    await notifyJetinno(o, pay.externalReference, 'PAYSUCCESS', paymentId);
    console.log(`[webhook] aprobado ${pay.externalReference} -> Jetinno notificado`);
  } catch (e) { console.error('[mp/webhook]', e.message); }
});

async function notifyJetinno(order, orderNo, payStatus, platBillNo) {
  const time = ts();
  const data = { deviceNo: order.deviceNo, orderNo, orderAmount: String(order.amountCents), payType: '1001', payStatus };
  if (platBillNo) data.platBillNo = String(platBillNo);
  const s = sign({ username: USERNAME, time, deviceNo: data.deviceNo, orderNo: data.orderNo, orderAmount: data.orderAmount, payType: data.payType, payStatus: data.payStatus }, APIKEY);
  const res = await fetch(order.notifyUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: USERNAME, time, sign: s, data }) });
  console.log(`[callback->Jetinno] ${orderNo} ${res.status} ${await res.text()}`);
}

app.get('/health', (_req, res) => res.json({ ok: true, mock: mpMock() }));
app.get('/', (_req, res) => res.send('Jetinno <-> MercadoPago bridge OK'));

app.listen(PORT, () => console.log(`Bridge escuchando en :${PORT} (mock=${mpMock()})`));
