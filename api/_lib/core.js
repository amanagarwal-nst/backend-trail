import { Redis } from '@upstash/redis';
import { SignJWT, jwtVerify } from 'jose';

/* ---------- database (Upstash Redis, via the Vercel Marketplace) ---------- */
let client = globalThis.__BT_REDIS || null;
export function db() {
  if (client) return client;
  const url = process.env.KV_REST_API_URL || process.env.AP_KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.AP_KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) throw new HttpError(500, 'Database is not connected. Add an Upstash Redis store to this Vercel project (see README).');
  client = new Redis({ url, token });
  return client;
}

export const K = {
  user: (e) => `bt:user:${e}`,
  progress: (e) => `bt:progress:${e}`,
  summary: (e) => `bt:summary:${e}`,
  students: 'bt:students',
  rate: (k) => `bt:rl:${k}`,
};

/* ---------- errors and responses ---------- */
export class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
export function send(res, status, data) {
  res.setHeader('Cache-Control', 'no-store');
  res.status(status).json(data);
}
export function wrap(fn) {
  return async (req, res) => {
    try {
      await fn(req, res);
    } catch (e) {
      if (e instanceof HttpError) return send(res, e.status, { error: e.message });
      console.error(e);
      send(res, 500, { error: 'Something went wrong on the server. Try again in a moment.' });
    }
  };
}
// Browsers cannot send a cross-site JSON request without a CORS preflight, which we never allow.
// Requiring JSON on every write is a simple CSRF guard on top of SameSite cookies.
export function requireJson(req) {
  const ct = String(req.headers['content-type'] || '');
  if (!ct.includes('application/json')) throw new HttpError(415, 'Send the request as JSON.');
  return req.body && typeof req.body === 'object' ? req.body : {};
}

/* ---------- sessions: a signed JWT in an HttpOnly cookie ---------- */
export const COOKIE = { student: 'bt_student', admin: 'bt_admin' };
const DAYS_7 = 60 * 60 * 24 * 7;

function secret() {
  const s = process.env.JWT_SECRET || '';
  if (s.length < 32) throw new HttpError(500, 'JWT_SECRET is missing or shorter than 32 characters. Set it in the Vercel project settings.');
  return new TextEncoder().encode(s);
}
export async function startSession(req, res, cookieName, payload, maxAge = DAYS_7) {
  const token = await new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(Math.floor(Date.now() / 1000) + maxAge)
    .sign(secret());
  setCookie(req, res, cookieName, token, maxAge);
}
export async function signToken(payload, maxAge) {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(Math.floor(Date.now() / 1000) + maxAge)
    .sign(secret());
}
export async function verifyToken(token) {
  try {
    const { payload } = await jwtVerify(token, secret(), { algorithms: ['HS256'] });
    return payload;
  } catch {
    return null;
  }
}
export function endSession(req, res, cookieName) {
  setCookie(req, res, cookieName, '', 0);
}
export async function readSession(req, cookieName, role) {
  const token = parseCookies(req)[cookieName];
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, secret(), { algorithms: ['HS256'] });
    return payload.role === role ? payload : null;
  } catch {
    return null;
  }
}
export function setCookie(req, res, name, value, maxAge) {
  const https = String(req.headers['x-forwarded-proto'] || '').includes('https');
  const parts = [`${name}=${value}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${maxAge}`];
  if (https) parts.push('Secure');
  const prev = res.getHeader('Set-Cookie');
  res.setHeader('Set-Cookie', prev ? [].concat(prev, parts.join('; ')) : parts.join('; '));
}
export function parseCookies(req) {
  const out = {};
  String(req.headers.cookie || '').split(';').forEach((c) => {
    const i = c.indexOf('=');
    if (i > 0) out[c.slice(0, i).trim()] = decodeURIComponent(c.slice(i + 1).trim());
  });
  return out;
}

/* ---------- validation ---------- */
export function cleanEmail(v) {
  const e = String(v || '').trim().toLowerCase();
  if (e.length > 120 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) throw new HttpError(400, 'Enter a valid email address.');
  return e;
}
export function allowedDomains() {
  return String(process.env.ALLOWED_EMAIL_DOMAINS || '')
    .split(',').map((d) => d.trim().toLowerCase().replace(/^@/, '')).filter(Boolean);
}
export function checkDomain(email) {
  const allowed = allowedDomains();
  if (!allowed.length) return;
  const domain = email.split('@')[1];
  if (!allowed.includes(domain)) {
    throw new HttpError(403, `Use your ${allowed.map((d) => '@' + d).join(' or ')} email address to sign up.`);
  }
}
/* ---------- Google sign-in setup ---------- */
export function googleEnabled() {
  return !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);
}
export function adminEmails() {
  return String(process.env.ADMIN_EMAILS || '')
    .split(',').map((e) => e.trim().toLowerCase()).filter(Boolean);
}

/* ---------- rate limiting (fixed window in Redis) ---------- */
export function clientIp(req) {
  return String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').split(',')[0].trim();
}
export async function rateLimit(key, max, windowSec) {
  const r = db();
  const k = K.rate(key);
  const n = await r.incr(k);
  if (n === 1) await r.expire(k, windowSec);
  if (n > max) throw new HttpError(429, 'Too many attempts. Wait 15 minutes and try again.');
}
