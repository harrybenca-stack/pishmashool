import { adapt, handleHunt, handleHuntPing } from './_lib.js';
// GET /api/hunt = وضعیت درخواست شکار (عمومی، برای شکارچی) — POST = خود شکار
export default adapt(async (req, db) => (req.method === 'GET' ? handleHuntPing(req, db) : handleHunt(req, db)));
