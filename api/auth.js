import {
  db, K, wrap, send, requireJson, HttpError, COOKIE,
  endSession, readSession, allowedDomains, googleEnabled,
} from './_lib/core.js';

// Students sign in only with Google (see api/google.js). This endpoint reports
// the setup, returns the signed-in student, and signs them out.
// /api/auth?action=config | me | logout
export default wrap(async (req, res) => {
  const action = String(req.query.action || '');

  if (action === 'config') {
    return send(res, 200, { google: googleEnabled(), domains: allowedDomains() });
  }

  if (action === 'me') {
    if (req.method !== 'GET') throw new HttpError(405, 'Use GET.');
    const s = await readSession(req, COOKIE.student, 'student');
    if (!s) return send(res, 401, { error: 'Not signed in.' });
    const u = await db().hgetall(K.user(s.sub));
    if (!u) {
      endSession(req, res, COOKIE.student);
      return send(res, 401, { error: 'This account no longer exists.' });
    }
    await db().hset(K.user(s.sub), { lastActive: Date.now() });
    return send(res, 200, { user: { name: String(u.name), email: String(u.email), picture: u.picture ? String(u.picture) : null } });
  }

  if (action === 'logout') {
    if (req.method !== 'POST') throw new HttpError(405, 'Use POST.');
    requireJson(req);
    endSession(req, res, COOKIE.student);
    return send(res, 200, { ok: true });
  }

  throw new HttpError(404, 'Unknown action.');
});
