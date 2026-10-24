import http from 'node:http';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, extname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

const root = dirname(fileURLToPath(import.meta.url));
const production = process.env.NODE_ENV === 'production';
const dataDir = process.env.DATA_DIR ? resolve(process.env.DATA_DIR) : join(root, 'data');
const dbFile = join(dataDir, 'store.json');
const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || (production ? '0.0.0.0' : '127.0.0.1');
const sessions = new Map();
const loginAttempts = new Map();
mkdirSync(dataDir, { recursive: true });

const hashPassword = (password, salt = randomBytes(16).toString('hex')) => ({ salt, hash: scryptSync(password, salt, 64).toString('hex') });
function load() {
  if (existsSync(dbFile)) return JSON.parse(readFileSync(dbFile, 'utf8'));
  const initialPassword = process.env.ADMIN_PASSWORD || (production ? '' : 'abc12345');
  if (initialPassword.length < (production ? 12 : 8)) {
    throw new Error(production ? '生产环境首次启动必须设置至少 12 位的 ADMIN_PASSWORD' : '初始管理员密码至少需要 8 位');
  }
  const admin = { id: 'u_admin', username: process.env.ADMIN_USERNAME || 'admin', name: '系统管理员', role: 'admin', ...hashPassword(initialPassword), mustChangePassword: true, active: true };
  const initial = { users: [admin], requests: [], audits: [{ id: randomBytes(8).toString('hex'), actor: '系统', action: '初始化系统', detail: '创建初始管理员账户', at: new Date().toISOString() }] };
  writeFileSync(dbFile, JSON.stringify(initial, null, 2));
  return initial;
}
let db = load();
const save = () => writeFileSync(dbFile, JSON.stringify(db, null, 2));
const safeUser = ({ id, username, name, role, mustChangePassword, active }) => ({ id, username, name, role, mustChangePassword, active });
const parseCookies = (header = '') => Object.fromEntries(header.split(';').map(x => x.trim().split('=').map(decodeURIComponent)).filter(x => x.length === 2));
function send(res, status, data, headers = {}) { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers }); res.end(JSON.stringify(data)); }
async function body(req) { let s = ''; for await (const c of req) s += c; return s ? JSON.parse(s) : {}; }
function actor(req) { const token = parseCookies(req.headers.cookie).sid; return sessions.get(token); }
function audit(user, action, detail) { db.audits.unshift({ id: randomBytes(8).toString('hex'), actor: user.name, action, detail, at: new Date().toISOString() }); save(); }
function auth(req, res, roles = []) { const user = actor(req); if (!user || !db.users.find(x => x.id === user.id && x.active)) { send(res, 401, { error: '请先登录' }); return null; } if (roles.length && !roles.includes(user.role)) { send(res, 403, { error: '当前账号没有此操作权限' }); return null; } return db.users.find(x => x.id === user.id); }
function amount(v) { const n = Number(v); if (!Number.isFinite(n) || n <= 0 || n > 999999999) throw new Error('金额需大于 0 且不超过 999,999,999'); return n.toFixed(2); }
function loginRateLimit(req) {
  const now = Date.now();
  const key = req.socket.remoteAddress || 'unknown';
  const entry = loginAttempts.get(key);
  if (!entry || now - entry.startedAt > 15 * 60 * 1000) { loginAttempts.set(key, { startedAt: now, count: 0 }); return { key, allowed: true }; }
  return { key, allowed: entry.count < 10 };
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  try {
    if (url.pathname.startsWith('/api/')) {
      if (req.method === 'GET' && url.pathname === '/api/health') return send(res, 200, { ok: true });
      if (req.method === 'POST' && url.pathname === '/api/login') {
        const limit = loginRateLimit(req);
        if (!limit.allowed) return send(res, 429, { error: '登录尝试过多，请 15 分钟后重试' });
        const { username, password } = await body(req);
        const user = db.users.find(x => x.username === String(username || '').trim() && x.active);
        const candidate = user && scryptSync(String(password || ''), user.salt, 64);
        if (!user || !candidate || !timingSafeEqual(candidate, Buffer.from(user.hash, 'hex'))) {
          const entry = loginAttempts.get(limit.key); if (entry) entry.count++;
          return send(res, 401, { error: '账号或密码错误' });
        }
        loginAttempts.delete(limit.key);
        const token = randomBytes(32).toString('hex'); sessions.set(token, { id: user.id });
        audit(user, '登录', '登录系统');
        return send(res, 200, { user: safeUser(user) }, { 'Set-Cookie': `sid=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${production ? '; Secure' : ''}` });
      }
      if (req.method === 'POST' && url.pathname === '/api/logout') { const token = parseCookies(req.headers.cookie).sid; sessions.delete(token); return send(res, 200, { ok: true }, { 'Set-Cookie': `sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${production ? '; Secure' : ''}` }); }
      const user = auth(req, res); if (!user) return;
      if (req.method === 'GET' && url.pathname === '/api/session') return send(res, 200, { user: safeUser(user) });
      if (req.method === 'POST' && url.pathname === '/api/password') {
        const { currentPassword, newPassword } = await body(req);
        const match = scryptSync(String(currentPassword || ''), user.salt, 64);
        if (!timingSafeEqual(match, Buffer.from(user.hash, 'hex'))) return send(res, 400, { error: '当前密码不正确' });
        if (String(newPassword || '').length < 8) return send(res, 400, { error: '新密码至少需要 8 位' });
        Object.assign(user, hashPassword(newPassword), { mustChangePassword: false }); audit(user, '修改密码', '更新登录密码'); return send(res, 200, { user: safeUser(user) });
      }
      if (user.mustChangePassword && url.pathname !== '/api/password') return send(res, 403, { error: '请先修改初始密码', code: 'PASSWORD_CHANGE_REQUIRED' });
      if (req.method === 'GET' && url.pathname === '/api/requests') {
        const requests = user.role === 'applicant' ? db.requests.filter(x => x.applicantId === user.id) : db.requests;
        return send(res, 200, { requests });
      }
      if (req.method === 'POST' && url.pathname === '/api/requests') {
        const b = await body(req); const kind = String(b.kind || '电子发票（普通发票）');
        const name = String(b.buyerName || '').trim(); const taxId = String(b.buyerTaxId || '').trim(); const item = String(b.itemName || '').trim();
        if (!name || !item) return send(res, 400, { error: '请填写购方名称和商品/服务名称' });
        if (!['电子发票（普通发票）', '电子发票（增值税专用发票）'].includes(kind)) return send(res, 400, { error: '发票类型无效' });
        const total = amount(b.amount); const rate = Number(b.taxRate);
        if (![0, 1, 3, 6, 9, 13].includes(rate)) return send(res, 400, { error: '请选择有效税率' });
        const record = { id: `FP-${new Date().toISOString().slice(0,10).replaceAll('-','')}-${randomBytes(3).toString('hex').toUpperCase()}`, buyerName: name, buyerTaxId: taxId, itemName: item, kind, amount: total, taxRate: rate, remark: String(b.remark || '').trim(), applicantId: user.id, applicantName: user.name, status: 'pending', createdAt: new Date().toISOString(), history: [{ action: '提交申请', by: user.name, at: new Date().toISOString() }] };
        db.requests.unshift(record); audit(user, '提交开票申请', `${record.id} · ${name} · ¥${total}`); save(); return send(res, 201, { request: record });
      }
      const requestAction = url.pathname.match(/^\/api\/requests\/([^/]+)\/(approve|reject|issue)$/);
      if (requestAction && req.method === 'POST') {
        const [, id, action] = requestAction; const record = db.requests.find(x => x.id === id); if (!record) return send(res, 404, { error: '未找到申请' });
        const bodyData = await body(req);
        if (action === 'approve' || action === 'reject') {
          if (!['admin', 'approver', 'finance'].includes(user.role)) return send(res, 403, { error: '需要审批权限' });
          if (record.status !== 'pending') return send(res, 400, { error: '该申请已处理' });
          record.status = action === 'approve' ? 'approved' : 'rejected'; record.reviewComment = String(bodyData.comment || '').trim(); record.reviewerName = user.name; record.reviewedAt = new Date().toISOString();
        } else {
          if (!['admin', 'finance'].includes(user.role)) return send(res, 403, { error: '需要开票权限' });
          if (record.status !== 'approved') return send(res, 400, { error: '只有审核通过的申请才能登记开票' });
          record.status = 'issued'; record.invoiceNo = String(bodyData.invoiceNo || '').trim(); record.issuedAt = new Date().toISOString(); record.issuerName = user.name;
        }
        const label = { approve: '审核通过', reject: '退回申请', issue: '登记开票' }[action]; record.history.push({ action: label, by: user.name, at: new Date().toISOString(), detail: record.reviewComment || record.invoiceNo || '' });
        audit(user, label, `${record.id}${record.invoiceNo ? ` · ${record.invoiceNo}` : ''}`); save(); return send(res, 200, { request: record });
      }
      if (req.method === 'GET' && url.pathname === '/api/users') { if (user.role !== 'admin') return send(res, 403, { error: '仅管理员可管理用户' }); return send(res, 200, { users: db.users.map(safeUser) }); }
      if (req.method === 'POST' && url.pathname === '/api/users') {
        if (user.role !== 'admin') return send(res, 403, { error: '仅管理员可管理用户' });
        const b = await body(req); const username = String(b.username || '').trim(); const name = String(b.name || '').trim();
        if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username) || !name || String(b.password || '').length < 8) return send(res, 400, { error: '用户名需为 3–32 位，姓名必填，密码至少 8 位' });
        if (db.users.some(x => x.username === username)) return send(res, 409, { error: '用户名已存在' });
        if (!['applicant', 'approver', 'finance', 'admin'].includes(b.role)) return send(res, 400, { error: '角色无效' });
        const created = { id: `u_${randomBytes(6).toString('hex')}`, username, name, role: b.role, ...hashPassword(b.password), mustChangePassword: true, active: true }; db.users.push(created); audit(user, '创建用户', `${username} · ${b.role}`); save(); return send(res, 201, { user: safeUser(created) });
      }
      if (req.method === 'GET' && url.pathname === '/api/audits') { if (!['admin', 'finance'].includes(user.role)) return send(res, 403, { error: '没有查看日志的权限' }); return send(res, 200, { audits: db.audits.slice(0, 100) }); }
      return send(res, 404, { error: '接口不存在' });
    }
    const requested = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
    const publicRoot = resolve(root, 'public');
    const path = resolve(publicRoot, requested);
    if (path !== publicRoot && !path.startsWith(publicRoot + sep)) return send(res, 403, { error: '禁止访问' });
    const content = readFileSync(path); const type = { '.html':'text/html; charset=utf-8', '.css':'text/css; charset=utf-8', '.js':'text/javascript; charset=utf-8', '.svg':'image/svg+xml' }[extname(path)] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-cache' }); res.end(content);
  } catch (e) { send(res, e.message.includes('金额') ? 400 : 500, { error: e.message || '服务器错误' }); }
});
server.listen(port, host, () => console.log(`发票系统已启动: http://${host}:${port}`));

