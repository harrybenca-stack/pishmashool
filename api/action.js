import { adapt, handleAction, handleAdminSeed, handleAdminPlanBReset, handleWebRequestSubmit, handleCorsPreflight } from './_lib.js';
// admin_seed/planb_reset (با کلید) + web_request_submit (فرم عمومی سایت پارلیا) + بقیه = اکشن‌های پنل
export default adapt(async (req, db) => {
  if (req.method === 'OPTIONS') return handleCorsPreflight(req);
  let b = req.body || {};
  if (typeof b === 'string') { try { b = JSON.parse(b); } catch (e) { b = {}; } }
  if (b && b.action === 'admin_seed') return handleAdminSeed(req, db);
  if (b && b.action === 'planb_reset') return handleAdminPlanBReset(req, db);
  if (b && b.action === 'web_request_submit') return handleWebRequestSubmit(req, db);
  return handleAction(req, db);
});
