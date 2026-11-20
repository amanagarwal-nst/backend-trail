import { db, K, wrap, send, requireJson, HttpError, COOKIE, readSession } from './_lib/core.js';

const MAX_BYTES = 300 * 1024;
const num = (v, lo, hi) => {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? Math.min(hi, Math.max(lo, Math.round(n))) : null;
};

// Keep only the known score fields, as clamped numbers, so the admin view never renders raw client input.
function cleanSummary(s) {
  s = s && typeof s === 'object' ? s : {};
  const days = Array.isArray(s.days) ? s.days.slice(0, 15) : [];
  return {
    daysDone: num(s.daysDone, 0, 15) ?? 0,
    checksDone: num(s.checksDone, 0, 1000) ?? 0,
    checksTotal: num(s.checksTotal, 0, 1000) ?? 0,
    accuracy: num(s.accuracy, 0, 100),
    answers: num(s.answers, 0, 1e6) ?? 0,
    xp: num(s.xp, 0, 1e7) ?? 0,
    level: num(s.level, 1, 1e5) ?? 1,
    mockBest: num(s.mockBest, 0, 100) ?? 0,
    missed: num(s.missed, 0, 10000) ?? 0,
    missions: num(s.missions, 0, 10000) ?? 0,
    predictions: num(s.predictions, 0, 10000) ?? 0,
    days: days.map((d, i) => ({
      n: i + 1,
      done: !!(d && d.done),
      checks: num(d && d.checks, 0, 100) ?? 0,
      checksTotal: num(d && d.checksTotal, 0, 100) ?? 0,
      quizBest: num(d && d.quizBest, 0, 100),
      attempts: num(d && d.attempts, 0, 10000) ?? 0,
      accuracy: num(d && d.accuracy, 0, 100),
      missed: num(d && d.missed, 0, 1000) ?? 0,
    })),
  };
}

export default wrap(async (req, res) => {
  const s = await readSession(req, COOKIE.student, 'student');
  if (!s) throw new HttpError(401, 'Sign in to save your progress.');
  const email = s.sub;
  const r = db();

  if (req.method === 'GET') {
    const rec = await r.get(K.progress(email));
    return send(res, 200, { progress: rec ? rec.p : null, updatedAt: rec ? rec.updatedAt : null });
  }

  if (req.method === 'PUT' || req.method === 'POST') {
    const body = requireJson(req);
    if (!body.p || typeof body.p !== 'object' || Array.isArray(body.p)) throw new HttpError(400, 'Missing progress data.');
    if (JSON.stringify(body.p).length > MAX_BYTES) throw new HttpError(413, 'Progress data is too large.');
    if (!(await r.exists(K.user(email)))) throw new HttpError(401, 'This account no longer exists.');

    const now = Date.now();
    const summary = { ...cleanSummary(body.summary), updatedAt: now };
    await r.set(K.progress(email), { p: body.p, updatedAt: now });
    await r.set(K.summary(email), summary);
    await r.hset(K.user(email), { lastActive: now });
    return send(res, 200, { ok: true, updatedAt: now });
  }

  throw new HttpError(405, 'Use GET or PUT.');
});
