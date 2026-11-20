import {
  db, K, wrap, send, requireJson, HttpError, COOKIE,
  endSession, readSession, cleanEmail, adminEmails,
} from './_lib/core.js';

// Admins sign in with Google too (api/google.js?as=admin); their email must be in ADMIN_EMAILS.
async function requireAdmin(req) {
  const s = await readSession(req, COOKIE.admin, 'admin');
  // Re-check the list on every request, so removing an email from ADMIN_EMAILS takes effect at once.
  if (!s || !adminEmails().includes(String(s.sub))) throw new HttpError(401, 'Sign in as admin.');
  return s;
}

function publicUser(u, summary) {
  return {
    name: String(u.name || ''),
    email: String(u.email || ''),
    picture: u.picture ? String(u.picture) : null,
    createdAt: Number(u.createdAt) || null,
    lastActive: Number(u.lastActive) || null,
    summary: summary || null,
  };
}

// /api/admin?action=logout | me | students | student | delete
export default wrap(async (req, res) => {
  const action = String(req.query.action || '');
  const r = () => db();

  if (action === 'logout') {
    if (req.method !== 'POST') throw new HttpError(405, 'Use POST.');
    requireJson(req);
    endSession(req, res, COOKIE.admin);
    return send(res, 200, { ok: true });
  }

  const admin = await requireAdmin(req);

  if (action === 'me') return send(res, 200, { admin: { email: admin.sub, name: admin.name || '' } });

  if (action === 'students') {
    if (req.method !== 'GET') throw new HttpError(405, 'Use GET.');
    const emails = (await r().smembers(K.students)) || [];
    if (!emails.length) return send(res, 200, { students: [] });
    const pipe = r().pipeline();
    emails.forEach((e) => { pipe.hgetall(K.user(e)); pipe.get(K.summary(e)); });
    const rows = await pipe.exec();
    const students = [];
    emails.forEach((e, i) => {
      const u = rows[i * 2];
      if (u) students.push(publicUser(u, rows[i * 2 + 1]));
    });
    return send(res, 200, { students });
  }

  if (action === 'student') {
    if (req.method !== 'GET') throw new HttpError(405, 'Use GET.');
    const email = cleanEmail(req.query.email);
    const u = await r().hgetall(K.user(email));
    if (!u) throw new HttpError(404, 'No student with that email.');
    const summary = await r().get(K.summary(email));
    return send(res, 200, { student: publicUser(u, summary) });
  }

  if (action === 'delete') {
    if (req.method !== 'POST') throw new HttpError(405, 'Use POST.');
    const email = cleanEmail(requireJson(req).email);
    await r().del(K.user(email), K.progress(email), K.summary(email));
    await r().srem(K.students, email);
    return send(res, 200, { ok: true });
  }

  throw new HttpError(404, 'Unknown action.');
});
