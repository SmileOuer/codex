import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { getDatabase } from '@netlify/database';

const db = getDatabase();
const roles = ['applicant', 'approver', 'finance', 'admin'];
const safeUser = ({ id, username, name, role, mustChangePassword, active }) => ({ id, username, name, role, mustChangePassword, active });
const hashPassword = (password, salt = randomBytes(16).toString('hex')) => ({ salt, hash: scryptSync(password, salt, 64).toString('hex') });
const cookieToken = (header = '') => header.split(';').map(x => x.trim()).find(x => x.startsWith('sid='))?.slice(4) || '';
const json = (data, status = 200, headers = {}) => Response.json(data, { status, headers: { 'Cache-Control': 'no-store', ...headers } });
const setSid = token => `sid=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800`;
const clearSid = 'sid=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0';
const recordAudit = (state, user, action, detail) => state.audits.unshift({ id: randomBytes(8).toString('hex'), actor: user.name, action, detail, at: new Date().toISOString() });

async function readBody(req) {
  try { return await req.json(); } catch { return {}; }
}
function amount(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0 || n > 999999999) throw new Error('金额需大于 0 且不超过 999,999,999');
  return n.toFixed(2);
}
function passwordMatches(password, user) {
  const candidate = scryptSync(String(password || ''), user.salt, 64);
  return timingSafeEqual(candidate, Buffer.from(user.hash, 'hex'));
}

export default async function handler(req) {
  const path = new URL(req.url).pathname.replace(/^\/\.netlify\/functions\/api/, '').replace(/^\/api/, '') || '/';
  if (req.method === 'GET' && path === '/health') return json({ ok: true });

  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`INSERT INTO app_state(singleton,payload) VALUES (TRUE,$1::jsonb) ON CONFLICT (singleton) DO NOTHING`, [JSON.stringify({ users: [], requests: [], audits: [] })]);
    const locked = await client.query('SELECT payload FROM app_state WHERE singleton = TRUE FOR UPDATE');
    const state = locked.rows[0].payload;
    if (!state.users.length) {
      const password = process.env.ADMIN_PASSWORD || '';
      if (password.length < 12) throw new Error('请在 Netlify 环境变量中配置至少 12 位 ADMIN_PASSWORD');
      const admin = { id: 'u_admin', username: process.env.ADMIN_USERNAME || 'admin', name: '系统管理员', role: 'admin', ...hashPassword(password), mustChangePassword: true, active: true };
      state.users.push(admin);
      recordAudit(state, { name: '系统' }, '初始化系统', '创建初始管理员账户');
    }
    const saveState = async () => client.query('UPDATE app_state SET payload=$1::jsonb, updated_at=NOW() WHERE singleton=TRUE', [JSON.stringify(state)]);
    const token = cookieToken(req.headers.get('cookie') || '');

    if (req.method === 'POST' && path === '/login') {
      const ip = req.headers.get('x-nf-client-connection-ip') || 'unknown';
      const recent = await client.query('SELECT started_at,count FROM login_attempts WHERE ip_key=$1 FOR UPDATE', [ip]);
      const now = Date.now();
      let attempts = recent.rows[0];
      if (!attempts || now - new Date(attempts.started_at).getTime() > 15 * 60 * 1000) {
        await client.query('INSERT INTO login_attempts(ip_key,started_at,count) VALUES($1,NOW(),0) ON CONFLICT(ip_key) DO UPDATE SET started_at=NOW(),count=0', [ip]);
        attempts = { count: 0 };
      }
      if (attempts.count >= 10) { await client.query('COMMIT'); return json({ error: '登录尝试过多，请 15 分钟后重试' }, 429); }
      const body = await readBody(req);
      const user = state.users.find(x => x.username === String(body.username || '').trim() && x.active);
      if (!user || !passwordMatches(body.password, user)) {
        await client.query('UPDATE login_attempts SET count=count+1 WHERE ip_key=$1', [ip]);
        await client.query('COMMIT');
        return json({ error: '账号或密码错误' }, 401);
      }
      await client.query('DELETE FROM login_attempts WHERE ip_key=$1', [ip]);
      const session = randomBytes(32).toString('hex');
      await client.query('INSERT INTO app_sessions(token,user_id,expires_at) VALUES($1,$2,NOW()+INTERVAL \'8 hours\')', [session, user.id]);
      recordAudit(state, user, '登录', '登录系统');
      await saveState(); await client.query('COMMIT');
      return json({ user: safeUser(user) }, 200, { 'Set-Cookie': setSid(session) });
    }

    if (req.method === 'POST' && path === '/logout') {
      if (token) await client.query('DELETE FROM app_sessions WHERE token=$1', [token]);
      await client.query('COMMIT'); return json({ ok: true }, 200, { 'Set-Cookie': clearSid });
    }

    const session = token ? await client.query('SELECT user_id FROM app_sessions WHERE token=$1 AND expires_at>NOW()', [token]) : { rows: [] };
    const user = state.users.find(x => x.id === session.rows[0]?.user_id && x.active);
    if (!user) { await client.query('COMMIT'); return json({ error: '请先登录' }, 401); }
    if (req.method === 'GET' && path === '/session') { await client.query('COMMIT'); return json({ user: safeUser(user) }); }
    if (req.method === 'POST' && path === '/password') {
      const body = await readBody(req);
      if (!passwordMatches(body.currentPassword, user)) { await client.query('COMMIT'); return json({ error: '当前密码不正确' }, 400); }
      if (String(body.newPassword || '').length < 8) { await client.query('COMMIT'); return json({ error: '新密码至少需要 8 位' }, 400); }
      Object.assign(user, hashPassword(body.newPassword), { mustChangePassword: false });
      recordAudit(state, user, '修改密码', '更新登录密码'); await saveState(); await client.query('COMMIT');
      return json({ user: safeUser(user) });
    }
    if (user.mustChangePassword) { await client.query('COMMIT'); return json({ error: '请先修改初始密码', code: 'PASSWORD_CHANGE_REQUIRED' }, 403); }

    if (req.method === 'GET' && path === '/requests') {
      const requests = user.role === 'applicant' ? state.requests.filter(x => x.applicantId === user.id) : state.requests;
      await client.query('COMMIT'); return json({ requests });
    }
    if (req.method === 'POST' && path === '/requests') {
      const b = await readBody(req); const kind = String(b.kind || '电子发票（普通发票）');
      const buyerName = String(b.buyerName || '').trim(); const itemName = String(b.itemName || '').trim();
      if (!buyerName || !itemName) throw new Error('请填写购方名称和商品/服务名称');
      if (!['电子发票（普通发票）', '电子发票（增值税专用发票）'].includes(kind)) throw new Error('发票类型无效');
      const total = amount(b.amount); const taxRate = Number(b.taxRate);
      if (![0, 1, 3, 6, 9, 13].includes(taxRate)) throw new Error('请选择有效税率');
      const record = { id: `FP-${new Date().toISOString().slice(0,10).replaceAll('-','')}-${randomBytes(3).toString('hex').toUpperCase()}`, buyerName, buyerTaxId: String(b.buyerTaxId || '').trim(), itemName, kind, amount: total, taxRate, remark: String(b.remark || '').trim(), applicantId: user.id, applicantName: user.name, status: 'pending', createdAt: new Date().toISOString(), history: [{ action: '提交申请', by: user.name, at: new Date().toISOString() }] };
      state.requests.unshift(record); recordAudit(state, user, '提交开票申请', `${record.id} · ${buyerName} · ¥${total}`);
      await saveState(); await client.query('COMMIT'); return json({ request: record }, 201);
    }
    const match = path.match(/^\/requests\/([^/]+)\/(approve|reject|issue)$/);
    if (match && req.method === 'POST') {
      const [, id, action] = match; const record = state.requests.find(x => x.id === id);
      if (!record) { await client.query('COMMIT'); return json({ error: '未找到申请' }, 404); }
      const b = await readBody(req);
      if (action === 'approve' || action === 'reject') {
        if (!['admin', 'approver', 'finance'].includes(user.role)) { await client.query('COMMIT'); return json({ error: '需要审批权限' }, 403); }
        if (record.status !== 'pending') { await client.query('COMMIT'); return json({ error: '该申请已处理' }, 400); }
        record.status = action === 'approve' ? 'approved' : 'rejected'; record.reviewComment = String(b.comment || '').trim(); record.reviewerName = user.name; record.reviewedAt = new Date().toISOString();
      } else {
        if (!['admin', 'finance'].includes(user.role)) { await client.query('COMMIT'); return json({ error: '需要开票权限' }, 403); }
        if (record.status !== 'approved') { await client.query('COMMIT'); return json({ error: '只有审核通过的申请才能登记开票' }, 400); }
        record.status = 'issued'; record.invoiceNo = String(b.invoiceNo || '').trim(); record.issuedAt = new Date().toISOString(); record.issuerName = user.name;
      }
      const label = { approve: '审核通过', reject: '退回申请', issue: '登记开票' }[action];
      record.history.push({ action: label, by: user.name, at: new Date().toISOString(), detail: record.reviewComment || record.invoiceNo || '' });
      recordAudit(state, user, label, `${record.id}${record.invoiceNo ? ` · ${record.invoiceNo}` : ''}`);
      await saveState(); await client.query('COMMIT'); return json({ request: record });
    }
    if (req.method === 'GET' && path === '/users') {
      if (user.role !== 'admin') { await client.query('COMMIT'); return json({ error: '仅管理员可管理用户' }, 403); }
      await client.query('COMMIT'); return json({ users: state.users.map(safeUser) });
    }
    if (req.method === 'POST' && path === '/users') {
      if (user.role !== 'admin') { await client.query('COMMIT'); return json({ error: '仅管理员可管理用户' }, 403); }
      const b = await readBody(req); const username = String(b.username || '').trim(); const name = String(b.name || '').trim();
      if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username) || !name || String(b.password || '').length < 8) throw new Error('用户名需为 3–32 位，姓名必填，密码至少 8 位');
      if (state.users.some(x => x.username === username)) { await client.query('COMMIT'); return json({ error: '用户名已存在' }, 409); }
      if (!roles.includes(b.role)) throw new Error('角色无效');
      const created = { id: `u_${randomBytes(6).toString('hex')}`, username, name, role: b.role, ...hashPassword(b.password), mustChangePassword: true, active: true };
      state.users.push(created); recordAudit(state, user, '创建用户', `${username} · ${b.role}`); await saveState(); await client.query('COMMIT'); return json({ user: safeUser(created) }, 201);
    }
    if (req.method === 'GET' && path === '/audits') {
      if (!['admin', 'finance'].includes(user.role)) { await client.query('COMMIT'); return json({ error: '没有查看日志的权限' }, 403); }
      await client.query('COMMIT'); return json({ audits: state.audits.slice(0, 100) });
    }
    await client.query('COMMIT'); return json({ error: '接口不存在' }, 404);
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    const status = /金额|购方名称|发票类型|税率|用户名|密码至少|角色无效/.test(error.message) ? 400 : 500;
    return json({ error: error.message || '服务器错误' }, status);
  } finally { client.release(); }
}

