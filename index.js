import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import Razorpay from 'razorpay';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import { createClient } from '@supabase/supabase-js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: Number(process.env.MAX_FILE_SIZE_BYTES || 5 * 1024 * 1024), files: 10 }
});

app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({ origin: process.env.APP_BASE_URL || true, credentials: false }));
// Razorpay webhook must receive the exact raw request body for HMAC verification.
app.use('/api/webhooks/razorpay', express.raw({ type: 'application/json', limit: '1mb' }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200, standardHeaders: true, legacyHeaders: false }));

const adminOtpSendLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 5, standardHeaders: true, legacyHeaders: false,
  keyGenerator: (req) => String(req.body?.mobile || '').trim() || 'unknown'
});
const adminOtpVerifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false,
  keyGenerator: (req) => String(req.body?.mobile || '').trim() || 'unknown'
});
app.use(express.static(path.join(__dirname, '..', 'public')));

const required = ['SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY', 'JWT_SECRET', 'ADMIN_ID', 'ADMIN_PASSWORD_HASH', 'ADMIN_MOBILES', 'MSG91_AUTHKEY', 'MSG91_TEMPLATE_ID'];
const missing = required.filter((key) => !process.env[key]);
if (missing.length) console.warn('Missing environment variables:', missing.join(', '));

const db = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false }
});
const razorpay = process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET
  ? new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET })
  : null;

const STATUS = ['NEW', 'DOCUMENT_CHECK', 'INFO_REQUIRED', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED'];
const allowedMimes = new Set(['image/jpeg', 'image/png', 'application/pdf']);

function makeId(prefix) {
  return `${prefix}-${new Date().getFullYear()}-${crypto.randomInt(0, 1000000).toString().padStart(6, '0')}`;
}
function adminMobiles() { return String(process.env.ADMIN_MOBILES || '').split(',').map(x => x.trim()).filter(Boolean); }
function signAdminToken(mobile) {
  return jwt.sign({ sub: process.env.ADMIN_ID, mobile, role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '2h' });
}
async function getAdminRecord(mobile) {
  const { data } = await db.from('admin_users').select('id,admin_id,mobile,password_hash,active').eq('mobile', mobile).eq('active', true).maybeSingle();
  return data || null;
}
async function passwordMatches(mobile, password) {
  const rec = await getAdminRecord(mobile);
  if (rec?.password_hash) return bcrypt.compare(password || '', rec.password_hash);
  return bcrypt.compare(password || '', process.env.ADMIN_PASSWORD_HASH || '');
}
function auth(req, res, next) {
  try {
    const raw = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    req.user = jwt.verify(raw, process.env.JWT_SECRET);
    if (req.user.role !== 'admin') throw new Error('Not admin');
    next();
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
  }
}

async function audit(actor, action, entityType, entityId, req) {
  await db.from('audit_logs').insert({
    actor, action, entity_type: entityType || null, entity_id: entityId || null,
    ip: req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || null
  });
}

async function sendOtp(mobile) {
  const response = await fetch('https://control.msg91.com/api/v5/otp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', authkey: process.env.MSG91_AUTHKEY },
    body: JSON.stringify({ template_id: process.env.MSG91_TEMPLATE_ID, mobile, otp_length: 6, otp_expiry: 5 })
  });
  if (!response.ok) throw new Error('OTP provider error');
  return response.json();
}
async function verifyOtp(otp, mobile) {
  const response = await fetch(`https://control.msg91.com/api/v5/otp/verify?otp=${encodeURIComponent(otp)}&mobile=${encodeURIComponent(mobile)}`, { headers: { authkey: process.env.MSG91_AUTHKEY } });
  if (!response.ok) return false;
  const data = await response.json();
  return data.type === 'success' || data.message === 'number_verified_successfully';
}

function safeEqualHex(a, b) {
  try {
    const aa = Buffer.from(String(a || ''), 'hex');
    const bb = Buffer.from(String(b || ''), 'hex');
    return aa.length === bb.length && aa.length > 0 && crypto.timingSafeEqual(aa, bb);
  } catch { return false; }
}

function razorpayWebhookSignature(rawBody) {
  return crypto.createHmac('sha256', process.env.RAZORPAY_WEBHOOK_SECRET || '').update(rawBody).digest('hex');
}

async function markPaymentFromRazorpay(orderId, paymentId, eventType, req) {
  if (!orderId) return false;
  const { data: application } = await db.from('applications').select('id,application_id,payment_order_id,payment_status').eq('payment_order_id', orderId).maybeSingle();
  if (!application) return false;

  const { error: eventError } = await db.from('payment_webhook_events').insert({
    event_id: req.headers['x-razorpay-event-id'] || crypto.createHash('sha256').update(`${eventType}|${orderId}|${paymentId || ''}`).digest('hex'),
    event_type: eventType, order_id: orderId, payment_id: paymentId
  });
  if (eventError && eventError.code === '23505') return true;
  if (eventError) throw eventError;

  const updates = { updated_at: new Date().toISOString() };
  if (paymentId) updates.payment_id = paymentId;
  if (eventType === 'payment.captured' || eventType === 'order.paid') updates.payment_status = 'PAID';
  else if (eventType === 'payment.failed' && application.payment_status !== 'PAID') updates.payment_status = 'FAILED';
  await db.from('applications').update(updates).eq('id', application.id);
  await audit('razorpay_webhook', `RAZORPAY_${eventType.toUpperCase().replaceAll('.', '_')}`, 'application', application.application_id, req);
  return true;
}

app.get('/api/health', async (req, res) => {
  const { error } = await db.from('services').select('id').limit(1);
  res.json({ ok: !error, database: !error ? 'connected' : 'error' });
});

app.get('/api/services', async (req, res) => {
  const { data, error } = await db.from('services').select('id,slug,name_hi,name_en,fee_paise,active,required_documents,form_schema').eq('active', true).order('name_hi');
  if (error) return res.status(500).json({ error: 'Could not load services' });
  res.json(data || []);
});

app.post('/api/admin/login', adminOtpSendLimiter, async (req, res) => {
  const { adminId, mobile, password } = req.body || {};
  const mobiles = adminMobiles();
  if (adminId !== process.env.ADMIN_ID || !mobiles.includes(String(mobile || '').trim()) || !(await passwordMatches(String(mobile).trim(), password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  try { await sendOtp(String(mobile).trim()); await audit(adminId, 'ADMIN_OTP_SENT', 'admin', mobile, req); res.json({ ok: true, otpRequired: true, mobile: String(mobile).trim() }); }
  catch { res.status(503).json({ error: 'OTP service unavailable' }); }
});

app.post('/api/admin/verify-otp', adminOtpVerifyLimiter, async (req, res) => {
  const mobile = String(req.body?.mobile || '').trim();
  if (!adminMobiles().includes(mobile) || !(await verifyOtp(req.body?.otp || '', mobile))) return res.status(401).json({ error: 'Invalid OTP' });
  const token = signAdminToken(mobile);
  await audit(process.env.ADMIN_ID, 'ADMIN_LOGIN', 'admin', mobile, req);
  res.json({ token });
});

app.post('/api/admin/change-password', auth, async (req, res) => {
  const currentPassword = req.body?.currentPassword || '';
  const newPassword = req.body?.newPassword || '';
  if (newPassword.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });
  if (!(await passwordMatches(req.user.mobile, currentPassword))) return res.status(401).json({ error: 'Current password is incorrect' });
  const hash = await bcrypt.hash(newPassword, 12);
  const { error } = await db.from('admin_users').upsert({ admin_id: process.env.ADMIN_ID, mobile: req.user.mobile, password_hash: hash, active: true }, { onConflict: 'mobile' });
  if (error) return res.status(500).json({ error: 'Could not change password' });
  await audit(process.env.ADMIN_ID, 'ADMIN_PASSWORD_CHANGED', 'admin', req.user.mobile, req);
  res.json({ ok: true });
});

app.post('/api/applications', upload.array('documents', 10), async (req, res) => {
  const { serviceId, applicantName, mobile, email, address, formData } = req.body || {};
  if (!serviceId || !applicantName || !mobile) return res.status(400).json({ error: 'Required fields missing' });

  const { data: service, error: serviceError } = await db.from('services')
    .select('*').eq('id', serviceId).eq('active', true).single();
  if (serviceError || !service) return res.status(400).json({ error: 'Service unavailable' });

  const applicationId = makeId('OLK');
  const { data: application, error } = await db.from('applications').insert({
    application_id: applicationId,
    service_id: service.id,
    applicant_name: applicantName.trim(),
    mobile: mobile.trim(),
    email: email?.trim() || null,
    address: address?.trim() || null,
    form_data: parseFormData(formData),
    fee_paise: service.fee_paise
  }).select('id,application_id,service_id,applicant_name,mobile,fee_paise,status,payment_status,created_at').single();
  if (error) return res.status(500).json({ error: 'Could not create application' });

  const files = req.files || [];
  for (const file of files) {
    if (!allowedMimes.has(file.mimetype)) continue;
    const safeName = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
    const storagePath = `${application.id}/${crypto.randomUUID()}-${safeName}`;
    const { error: uploadError } = await db.storage.from('private-documents').upload(storagePath, file.buffer, {
      contentType: file.mimetype,
      upsert: false
    });
    if (uploadError) continue;
    await db.from('documents').insert({
      application_id: application.id,
      storage_path: storagePath,
      original_name: file.originalname,
      mime_type: file.mimetype,
      size_bytes: file.size
    });
  }

  res.json(application);
});

function parseFormData(value) {
  if (!value) return {};
  if (typeof value === 'object') return value;
  try { return JSON.parse(value); } catch { return { additional_information: String(value) }; }
}

app.get('/api/applications/:id', async (req, res) => {
  const { data, error } = await db.from('applications')
    .select('application_id,status,payment_status,created_at,updated_at,services(name_hi,name_en)')
    .eq('application_id', req.params.id).single();
  if (error || !data) return res.status(404).json({ error: 'Application not found' });
  res.json(data);
});

app.post('/api/inquiries', async (req, res) => {
  const { name, mobile, serviceId, message } = req.body || {};
  if (!name || !mobile || !message) return res.status(400).json({ error: 'Required fields missing' });
  const { data, error } = await db.from('inquiries').insert({
    inquiry_id: makeId('INQ'), name: name.trim(), mobile: mobile.trim(), service_id: serviceId || null, message: message.trim()
  }).select('inquiry_id,created_at').single();
  if (error) return res.status(500).json({ error: 'Could not create inquiry' });
  res.json(data);
});

app.post('/api/applications/:id/payment-order', async (req, res) => {
  if (!razorpay) return res.status(503).json({ error: 'Online payment is not configured yet' });
  const { data: application } = await db.from('applications').select('*').eq('application_id', req.params.id).single();
  if (!application) return res.status(404).json({ error: 'Application not found' });
  if (!application.fee_paise) return res.status(400).json({ error: 'No fee due' });
  const order = await razorpay.orders.create({ amount: application.fee_paise, currency: 'INR', receipt: application.application_id, payment_capture: 1 });
  await db.from('applications').update({ payment_order_id: order.id, updated_at: new Date().toISOString() }).eq('id', application.id);
  res.json({ keyId: process.env.RAZORPAY_KEY_ID, orderId: order.id, amount: order.amount, currency: order.currency });
});

app.post('/api/payments/verify', async (req, res) => {
  const { applicationId, razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body || {};
  const { data: application } = await db.from('applications').select('*').eq('application_id', applicationId).single();
  if (!application || application.payment_order_id !== razorpay_order_id) return res.status(400).json({ error: 'Order mismatch' });

  const expected = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update(`${application.payment_order_id}|${razorpay_payment_id}`).digest('hex');
  if (!safeEqualHex(expected, razorpay_signature)) return res.status(400).json({ error: 'Payment signature verification failed' });

  if (!razorpay) return res.status(503).json({ error: 'Online payment is not configured yet' });
  let payment;
  try { payment = await razorpay.payments.fetch(razorpay_payment_id); }
  catch { return res.status(502).json({ error: 'Could not verify payment with Razorpay' }); }

  if (payment.order_id !== application.payment_order_id || Number(payment.amount) !== Number(application.fee_paise) || payment.currency !== 'INR') {
    return res.status(400).json({ error: 'Payment details do not match the application order' });
  }

  const status = String(payment.status || '').toLowerCase();
  const paymentStatus = status === 'captured' ? 'PAID' : status === 'authorized' ? 'AUTHORIZED' : status === 'failed' ? 'FAILED' : 'PENDING';
  await db.from('applications').update({ payment_status: paymentStatus, payment_id: razorpay_payment_id, payment_signature: razorpay_signature, updated_at: new Date().toISOString() }).eq('id', application.id);
  await audit('payment', 'PAYMENT_VERIFIED', 'application', application.application_id, req);
  res.json({ ok: true, paymentStatus });
});

app.post('/api/webhooks/razorpay', async (req, res) => {
  if (!process.env.RAZORPAY_WEBHOOK_SECRET) return res.status(503).json({ error: 'Webhook secret is not configured' });
  const rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.from(JSON.stringify(req.body || {}));
  const signature = req.headers['x-razorpay-signature'];
  if (!safeEqualHex(razorpayWebhookSignature(rawBody), signature)) return res.status(400).json({ error: 'Invalid webhook signature' });

  try {
    const payload = JSON.parse(rawBody.toString('utf8'));
    const event = payload.event;
    const payment = payload.payload?.payment?.entity;
    const order = payload.payload?.order?.entity;
    const orderId = payment?.order_id || order?.id;
    const paymentId = payment?.id;
    if (['payment.captured', 'payment.failed', 'order.paid'].includes(event)) {
      await markPaymentFromRazorpay(orderId, paymentId, event, req);
    }
    res.json({ ok: true });
  } catch (error) {
    console.error('Razorpay webhook error:', error);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

app.get('/api/admin/dashboard', auth, async (req, res) => {
  const [{ data: applications }, { data: inquiries }, { data: services }, { data: documents }] = await Promise.all([
    db.from('applications').select('id,application_id,applicant_name,mobile,email,service_id,fee_paise,status,payment_status,created_at,updated_at,services(name_hi,name_en)').order('created_at', { ascending: false }).limit(200),
    db.from('inquiries').select('id,inquiry_id,name,mobile,service_id,message,status,created_at,updated_at,services(name_hi,name_en)').order('created_at', { ascending: false }).limit(200),
    db.from('services').select('*').order('name_hi'),
    db.from('documents').select('id,application_id,original_name,mime_type,size_bytes,created_at').order('created_at', { ascending: false }).limit(500)
  ]);
  res.json({ applications: applications || [], inquiries: inquiries || [], services: services || [], documents: documents || [] });
});

app.patch('/api/admin/applications/:id/status', auth, async (req, res) => {
  if (!STATUS.includes(req.body.status)) return res.status(400).json({ error: 'Invalid status' });
  const { error } = await db.from('applications').update({ status: req.body.status, updated_at: new Date().toISOString() }).eq('application_id', req.params.id);
  if (error) return res.status(500).json({ error: 'Could not update status' });
  await audit(process.env.ADMIN_ID, 'APPLICATION_STATUS_UPDATE', 'application', req.params.id, req);
  res.json({ ok: true });
});

app.patch('/api/admin/inquiries/:id/status', auth, async (req, res) => {
  const allowed = ['NEW', 'CONTACTED', 'RESOLVED', 'CLOSED'];
  if (!allowed.includes(req.body.status)) return res.status(400).json({ error: 'Invalid status' });
  const { error } = await db.from('inquiries').update({ status: req.body.status, updated_at: new Date().toISOString() }).eq('inquiry_id', req.params.id);
  if (error) return res.status(500).json({ error: 'Could not update inquiry' });
  await audit(process.env.ADMIN_ID, 'INQUIRY_STATUS_UPDATE', 'inquiry', req.params.id, req);
  res.json({ ok: true });
});

app.patch('/api/admin/services/:id', auth, async (req, res) => {
  const updates = {};
  if (req.body.fee_paise !== undefined) {
    const fee = Number(req.body.fee_paise);
    if (!Number.isInteger(fee) || fee < 0) return res.status(400).json({ error: 'Invalid fee' });
    updates.fee_paise = fee;
  }
  if (req.body.active !== undefined) updates.active = Boolean(req.body.active);
  if (!Object.keys(updates).length) return res.status(400).json({ error: 'No changes supplied' });
  updates.updated_at = new Date().toISOString();
  const { error } = await db.from('services').update(updates).eq('id', req.params.id);
  if (error) return res.status(500).json({ error: 'Could not update service' });
  await audit(process.env.ADMIN_ID, 'SERVICE_UPDATE', 'service', req.params.id, req);
  res.json({ ok: true });
});

app.get('/api/admin/documents/:id/url', auth, async (req, res) => {
  const { data: doc } = await db.from('documents').select('*').eq('id', req.params.id).single();
  if (!doc) return res.status(404).json({ error: 'Document not found' });
  const { data, error } = await db.storage.from('private-documents').createSignedUrl(doc.storage_path, 600);
  if (error) return res.status(500).json({ error: 'Could not create document URL' });
  res.json({ url: data.signedUrl, name: doc.original_name });
});

const pageMap = {'/':'index.html','/about':'about.html','/services':'services.html','/apply':'apply.html','/track':'track.html','/inquiry':'inquiry.html','/fees':'fees.html','/contact':'contact.html','/admin':'admin.html'};
app.get('/{*splat}', (req, res) => {
  const file = pageMap[req.path];
  if (file) return res.sendFile(path.join(__dirname, '..', 'public', file));
  return res.status(404).send('Page not found');
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`Om Lokvani server ready on port ${port}`));
