// HAZARD 7007 Blue — single-owner invite + device-bound browser sessions.
// Node 20+. npm install, then set ADMIN_PASSWORD and SESSION_SECRET before start.
const express = require('express');
const crypto = require('node:crypto');
const Database = require('better-sqlite3');
const path = require('node:path');
const app = express();
const db = new Database(process.env.DB_FILE || path.join(__dirname, 'hazard.sqlite'));
const PORT = Number(process.env.PORT || 3000);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 14 || !SESSION_SECRET || SESSION_SECRET.length < 32) {
  throw new Error('Set ADMIN_PASSWORD (14+ chars) and SESSION_SECRET (32+ chars).');
}
app.set('trust proxy', 1);
app.use(express.json({limit:'10kb'}));
const secure = process.env.NODE_ENV === 'production';
const cookie = (name, value, maxAge) => `${name}=${value}; HttpOnly; Path=/; SameSite=Strict; Max-Age=${maxAge}${secure?'; Secure':''}`;
const clearCookie = name => `${name}=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0${secure?'; Secure':''}`;
const hash = s => crypto.createHmac('sha256', SESSION_SECRET).update(s).digest('hex');
const token = () => crypto.randomBytes(32).toString('base64url');
db.exec(`CREATE TABLE IF NOT EXISTS invites(token_hash TEXT PRIMARY KEY, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER);
CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY, session_hash TEXT UNIQUE NOT NULL, created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL, revoked_at INTEGER);
CREATE TABLE IF NOT EXISTS admins(session_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);`);
app.use(express.static(__dirname, {index:false}));
function getCookie(req,n){const v=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(n+'='));return v?decodeURIComponent(v.slice(n.length+1)):''}
function admin(req,res,next){const s=getCookie(req,'hz_admin');const row=s&&db.prepare('SELECT expires_at FROM admins WHERE session_hash=?').get(hash(s));if(!row||row.expires_at<Date.now())return res.status(401).json({error:'Требуется вход владельца'});next()}
function member(req,res,next){const s=getCookie(req,'hz_device');const row=s&&db.prepare('SELECT id,revoked_at FROM devices WHERE session_hash=?').get(hash(s));if(!row||row.revoked_at)return res.status(401).json({error:'Доступ не активен'});db.prepare('UPDATE devices SET last_seen=? WHERE id=?').run(Date.now(),row.id);req.device=row;next()}
app.post('/api/admin/login',(req,res)=>{const supplied=crypto.createHash('sha256').update(String(req.body.password||'')).digest();const expected=crypto.createHash('sha256').update(ADMIN_PASSWORD).digest();if(!crypto.timingSafeEqual(supplied,expected)){return res.status(401).json({error:'Неверный пароль'})}const s=token();db.prepare('INSERT INTO admins VALUES(?,?)').run(hash(s),Date.now()+7*86400000);res.setHeader('Set-Cookie',cookie('hz_admin',s,7*86400));res.json({ok:true})});
app.post('/api/admin/logout',admin,(req,res)=>{db.prepare('DELETE FROM admins WHERE session_hash=?').run(hash(getCookie(req,'hz_admin')));res.setHeader('Set-Cookie',clearCookie('hz_admin'));res.json({ok:true})});
app.get('/api/admin/me',admin,(_req,res)=>res.json({ok:true}));
app.post('/api/invite',admin,(req,res)=>{const raw=token(), now=Date.now(), hours=Math.min(168,Math.max(1,Number(req.body.hours)||24));db.prepare('INSERT INTO invites VALUES(?,?,?,NULL)').run(hash(raw),now,now+hours*3600000);res.json({url:`${req.protocol}://${req.get('host')}/?invite=${raw}`,expiresAt:now+hours*3600000})});
app.get('/api/invites',admin,(_req,res)=>{const rows=db.prepare('SELECT created_at,expires_at,used_at FROM invites ORDER BY created_at DESC LIMIT 100').all();res.json({invites:rows.map(x=>({...x,status:x.used_at?'Использована':x.expires_at<Date.now()?'Истекла':'Активна'}))})});
app.get('/api/devices',admin,(_req,res)=>res.json({devices:db.prepare('SELECT id,created_at,last_seen,revoked_at FROM devices ORDER BY created_at DESC').all()}));
app.post('/api/devices/:id/revoke',admin,(req,res)=>{db.prepare('UPDATE devices SET revoked_at=? WHERE id=?').run(Date.now(),req.params.id);res.json({ok:true})});
app.post('/api/activate',(req,res)=>{const raw=String(req.body.invite||'');if(raw.length<30||raw.length>100)return res.status(400).json({error:'Некорректная ссылка'});const row=db.prepare('SELECT * FROM invites WHERE token_hash=?').get(hash(raw));if(!row||row.used_at||row.expires_at<Date.now())return res.status(410).json({error:'Приглашение уже использовано или истекло'});const s=token(),id=crypto.randomUUID(),now=Date.now();const tx=db.transaction(()=>{const changed=db.prepare('UPDATE invites SET used_at=? WHERE token_hash=? AND used_at IS NULL AND expires_at>?').run(now,hash(raw),now);if(!changed.changes)throw Error('USED');db.prepare('INSERT INTO devices VALUES(?,?,?,?,NULL)').run(id,hash(s),now,now)});try{tx()}catch{return res.status(410).json({error:'Приглашение уже использовано или истекло'})}res.setHeader('Set-Cookie',cookie('hz_device',s,365*86400));res.json({ok:true})});
app.get('/api/member',member,(req,res)=>res.json({ok:true,deviceId:req.device.id}));
app.post('/api/member/logout',member,(req,res)=>{db.prepare('UPDATE devices SET revoked_at=? WHERE id=?').run(Date.now(),req.device.id);res.setHeader('Set-Cookie',clearCookie('hz_device'));res.json({ok:true})});
app.get('/',(_req,res)=>res.sendFile(path.join(__dirname,'index.html')));
app.listen(PORT,()=>console.log(`HAZARD Blue listening on ${PORT}`));
