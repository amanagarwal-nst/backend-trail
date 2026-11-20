import crypto from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import {
  db, K, HttpError, COOKIE, startSession, signToken, verifyToken,
  setCookie, parseCookies, checkDomain, allowedDomains, adminEmails, googleEnabled, clientIp, rateLimit,
} from './_lib/core.js';

// GET /api/google            -> sends a student to Google's account picker
// GET /api/google?as=admin   -> same, for the admin dashboard
// GET /api/google?code=...   -> Google sends them back here (this URL is the redirect URI)

const AUTH_URL = globalThis.__BT_GOOGLE_AUTH_URL || 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];
const FLOW_COOKIE = 'bt_oauth';
const FLOW_TTL = 600; // 10 minutes to finish signing in at Google

let jwks = globalThis.__BT_GOOGLE_JWKS || null;
const googleKeys = () => (jwks ||= createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs')));

const b64url = (buf) => buf.toString('base64url');

function redirectUri(req) {
  if (process.env.APP_URL) return process.env.APP_URL.replace(/\/+$/, '') + '/api/google';
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  const proto = String(req.headers['x-forwarded-proto'] || 'https').split(',')[0];
  return `${proto}://${host}/api/google`;
}

function redirect(res, location) {
  res.setHeader('Cache-Control', 'no-store');
  res.statusCode = 302;
  res.setHeader('Location', location);
  res.end();
}
// Errors go back to the sign-in screen as a short code; the page turns it into a message.
const fail = (req, res, code, admin) => {
  setCookie(req, res, FLOW_COOKIE, '', 0);
  redirect(res, (admin ? '/admin' : '/') + '?auth_error=' + encodeURIComponent(code));
};

async function start(req, res) {
  await rateLimit('google:' + clientIp(req), 30, 900);
  const admin = req.query.as === 'admin';
  const state = b64url(crypto.randomBytes(24));
  const nonce = b64url(crypto.randomBytes(24));
  const verifier = b64url(crypto.randomBytes(48));
  const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());

  // state, nonce and the PKCE verifier ride in a signed, HttpOnly, 10-minute cookie.
  setCookie(req, res, FLOW_COOKIE, await signToken({ state, nonce, verifier, admin }, FLOW_TTL), FLOW_TTL);

  const params = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: redirectUri(req),
    response_type: 'code',
    scope: 'openid email profile',
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    prompt: 'select_account',
  });
  const domains = allowedDomains();
  if (!admin && domains.length === 1) params.set('hd', domains[0]); // pre-filters the account picker; still enforced below
  redirect(res, `${AUTH_URL}?${params}`);
}

// Only keep a profile photo URL that really is Google's, since the admin page shows it.
const picture = (c) => (typeof c.picture === 'string' && /^https:\/\/[a-z0-9-]+\.googleusercontent\.com\//.test(c.picture) ? { picture: c.picture } : {});

async function callback(req, res) {
  const q = req.query;
  const flow = await verifyToken(parseCookies(req)[FLOW_COOKIE] || '');
  const admin = !!(flow && flow.admin);
  if (q.error) return fail(req, res, q.error === 'access_denied' ? 'cancelled' : 'failed', admin);
  if (!flow || !q.state || q.state !== flow.state) return fail(req, res, 'expired', admin);

  // Exchange the one-time code (plus the PKCE verifier) for tokens, server to server.
  const tokenRes = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code: String(q.code),
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      redirect_uri: redirectUri(req),
      grant_type: 'authorization_code',
      code_verifier: flow.verifier,
    }),
  });
  const tokens = await tokenRes.json().catch(() => ({}));
  if (!tokenRes.ok || !tokens.id_token) {
    console.error('Google token exchange failed', tokenRes.status, tokens.error);
    return fail(req, res, 'failed', admin);
  }

  // Verify the ID token's signature, issuer, audience and expiry, then our nonce.
  let claims;
  try {
    ({ payload: claims } = await jwtVerify(tokens.id_token, googleKeys(), {
      issuer: ISSUERS,
      audience: process.env.GOOGLE_CLIENT_ID,
    }));
  } catch (e) {
    console.error('Google ID token rejected', e.code || e.message);
    return fail(req, res, 'failed', admin);
  }
  if (claims.nonce !== flow.nonce) return fail(req, res, 'failed', admin);
  if (!claims.email || claims.email_verified !== true) return fail(req, res, 'unverified', admin);

  const email = String(claims.email).toLowerCase();

  if (admin) {
    if (!adminEmails().includes(email)) return fail(req, res, 'notadmin', true);
    setCookie(req, res, FLOW_COOKIE, '', 0);
    await startSession(req, res, COOKIE.admin, { sub: email, role: 'admin', name: String(claims.name || '') }, 60 * 60 * 12);
    return redirect(res, '/admin');
  }

  try { checkDomain(email); } catch { return fail(req, res, 'domain'); }

  const r = db();
  const existing = await r.hgetall(K.user(email));
  const now = Date.now();
  if (existing) {
    // Same email, different Google account: refuse rather than merge.
    if (existing.googleSub && String(existing.googleSub) !== String(claims.sub)) return fail(req, res, 'conflict');
    await r.hset(K.user(email), { googleSub: String(claims.sub), lastActive: now, ...picture(claims) });
  } else {
    const name = String(claims.name || email.split('@')[0]).trim().slice(0, 80);
    await r.hset(K.user(email), { name, email, googleSub: String(claims.sub), createdAt: now, lastActive: now, ...picture(claims) });
    await r.sadd(K.students, email);
  }

  setCookie(req, res, FLOW_COOKIE, '', 0);
  await startSession(req, res, COOKIE.student, { sub: email, role: 'student' });
  redirect(res, '/');
}

export default async function handler(req, res) {
  try {
    if (req.method !== 'GET') throw new HttpError(405, 'Use GET.');
    if (!googleEnabled()) return fail(req, res, 'disabled', req.query.as === 'admin');
    if (req.query.code || req.query.error) return await callback(req, res);
    return await start(req, res);
  } catch (e) {
    console.error(e);
    const admin = req.query.as === 'admin';
    if (e instanceof HttpError && e.status === 429) return fail(req, res, 'ratelimit', admin);
    return fail(req, res, 'failed', admin);
  }
}
