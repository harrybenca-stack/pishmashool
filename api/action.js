import { adapt, handleAction, handleAdminSeed, handleAdminPlanBReset } from './_lib.js';
// action=admin_seed (با کلید شکارچی) = سید شرکت‌های شکار تازه؛ action=planb_reset (با کلید) = ریست رمز پلن B؛ بقیه = اکشن‌های کارت
export default adapt(async (req, db) => {
  let b = req.body || {};
  if (typeof b === 'string') { try { b = JSON.parse(b); } catch (e) { b = {}; } }
  if (b && b.action === 'admin_seed') return handleAdminSeed(req, db);
  if (b && b.action === 'planb_reset') return handleAdminPlanBReset(req, db);
  return handleAction(req, db);
});
