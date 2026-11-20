import { adapt, handleAction, handleAdminSeed } from './_lib.js';
// action=admin_seed (با کلید شکارچی) = سید شرکت‌های شکار تازه؛ بقیه = اکشن‌های کارت
export default adapt(async (req, db) => {
  let b = req.body || {};
  if (typeof b === 'string') { try { b = JSON.parse(b); } catch (e) { b = {}; } }
  return b && b.action === 'admin_seed' ? handleAdminSeed(req, db) : handleAction(req, db);
});
