import { handleState, makeDb, parseQuery } from './_lib.js';
export default async (req, res) => {
  try {
    req.query = parseQuery(req);
    const out = await handleState(req, makeDb());
    if (out.headers) for (const [k, v] of Object.entries(out.headers)) res.setHeader(k, v);
    res.status(out.status).json(out.json);
  } catch (e) {
    console.error('pm state error:', e);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
};
