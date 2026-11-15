import { handleLogout } from './_lib.js';
export default async (req, res) => {
  const out = await handleLogout(req);
  if (out.headers) for (const [k, v] of Object.entries(out.headers)) res.setHeader(k, v);
  res.status(out.status).json(out.json);
};
