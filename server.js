const http=require('http');
const fs=require('fs');
const path=require('path');
const crypto=require('crypto');
const {Pool}=require('pg');
const multer=require('multer');
const {S3Client,PutObjectCommand,GetObjectCommand,DeleteObjectCommand}=require('@aws-sdk/client-s3');

const PORT=Number(process.env.PORT||3000),ROOT=__dirname,PUBLIC=path.join(ROOT,'public');
const DATABASE_URL=process.env.DATABASE_URL||process.env.POSTGRES_URL||'';
const NODE_ENV=process.env.NODE_ENV||'development';
if(!DATABASE_URL){console.error('DATABASE_URL/POSTGRES_URL is required. Antideploy should provide Postgres.');process.exit(1)}

const pool=new Pool({connectionString:DATABASE_URL,ssl:process.env.PGSSLMODE==='disable'?false:{rejectUnauthorized:false},max:5});
const sessions=new Map();
const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:15*1024*1024}});

function s3Config(){
  const bucket=process.env.S3_BUCKET||process.env.AWS_S3_BUCKET;
  const region=process.env.S3_REGION||process.env.AWS_REGION||'auto';
  const endpoint=process.env.S3_ENDPOINT||process.env.AWS_S3_ENDPOINT;
  const accessKeyId=process.env.S3_ACCESS_KEY_ID||process.env.AWS_ACCESS_KEY_ID;
  const secretAccessKey=process.env.S3_SECRET_ACCESS_KEY||process.env.AWS_SECRET_ACCESS_KEY;
  return {bucket,region,endpoint,accessKeyId,secretAccessKey};
}
function s3(){const c=s3Config();if(!c.bucket||!c.accessKeyId||!c.secretAccessKey)throw Error('S3 object storage is not configured');return new S3Client({region:c.region,endpoint:c.endpoint||undefined,forcePathStyle:process.env.S3_FORCE_PATH_STYLE==='true',credentials:{accessKeyId:c.accessKeyId,secretAccessKey:c.secretAccessKey}})}
function makeId(prefix){return prefix+'_'+Date.now().toString(36)+'_'+crypto.randomBytes(6).toString('hex')}
function passwordHash(password,salt=crypto.randomBytes(16).toString('hex')){return {salt,hash:crypto.scryptSync(password,salt,64).toString('hex')}}
function passwordVerify(password,x){try{return crypto.timingSafeEqual(Buffer.from(passwordHash(password,x.salt).hash,'hex'),Buffer.from(x.password_hash,'hex'))}catch{return false}}
function send(res,status,data,headers={}){if(status===204){res.writeHead(204,headers);return res.end()}const body=typeof data==='string'?data:JSON.stringify(data);res.writeHead(status,{'Content-Type':'application/json; charset=utf-8',...headers});res.end(body)}
function json(req){return new Promise((resolve,reject)=>{let raw='';req.on('data',c=>{raw+=c;if(raw.length>5e6)req.destroy()});req.on('end',()=>{try{resolve(raw?JSON.parse(raw):{})}catch(e){reject(e)}});req.on('error',reject)})}
function auth(req){const token=(req.headers.authorization||'').replace(/^Bearer\s+/,'');return sessions.get(token)||null}
async function q(text,params=[]){return (await pool.query(text,params)).rows}
async function one(text,params=[]){const r=await q(text,params);return r[0]||null}

async function migrate(){
 await q(`CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,password_salt TEXT NOT NULL,name TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'owner',created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`);
 await q(`CREATE TABLE IF NOT EXISTS companies(id TEXT PRIMARY KEY,name TEXT NOT NULL,owner_id TEXT NOT NULL REFERENCES users(id),created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`);
 await q(`CREATE TABLE IF NOT EXISTS company_members(company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,role TEXT NOT NULL DEFAULT 'member',created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),PRIMARY KEY(company_id,user_id));`);
 await q(`CREATE TABLE IF NOT EXISTS records(id TEXT PRIMARY KEY,company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,kind TEXT NOT NULL,payload JSONB NOT NULL DEFAULT '{}'::jsonb,created_by TEXT REFERENCES users(id),created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`);
 await q(`CREATE INDEX IF NOT EXISTS records_company_kind_idx ON records(company_id,kind,created_at DESC);`);
 await q(`CREATE TABLE IF NOT EXISTS receipts(id TEXT PRIMARY KEY,company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,original_name TEXT NOT NULL,mime_type TEXT NOT NULL,size_bytes INTEGER NOT NULL,object_key TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'uploaded',extracted JSONB,created_by TEXT REFERENCES users(id),created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`);
}
function publicUser(u){return {id:u.id,name:u.name,email:u.email,role:u.role}}
async function companiesFor(userId){return await q(`SELECT c.id,c.name,c.owner_id AS "ownerId",c.created_at AS "createdAt",COALESCE(cm.role,'owner') AS role FROM companies c LEFT JOIN company_members cm ON cm.company_id=c.id AND cm.user_id=$1 WHERE c.owner_id=$1 OR cm.user_id=$1 ORDER BY c.created_at`,[userId])}
async function canCompany(userId,companyId){return !!await one(`SELECT 1 FROM companies c LEFT JOIN company_members cm ON cm.company_id=c.id AND cm.user_id=$1 WHERE c.id=$2 AND (c.owner_id=$1 OR cm.user_id=$1)`,[userId,companyId])}
function rowToRecord(r){return {id:r.id,...r.payload,companyId:r.company_id,createdBy:r.created_by,createdAt:r.created_at,updatedAt:r.updated_at}}

async function api(req,res,u){
 const parts=u.pathname.split('/').filter(Boolean),route=parts[1],rid=parts[2];
 if(u.pathname==='/api/health')return send(res,200,{ok:true,service:'Acoot Smart Books v4',database:'postgres',objectStorage:!!s3Config().bucket,time:new Date().toISOString()});
 if(route==='register'&&req.method==='POST'){
   const x=await json(req),email=String(x.email||'').trim().toLowerCase(),pass=String(x.password||'');
   if(!email||pass.length<6)return send(res,400,{error:'Valid email and password (6+ chars) required'});
   if(await one('SELECT 1 FROM users WHERE email=$1',[email]))return send(res,409,{error:'Email already registered'});
   const id=makeId('usr'),h=passwordHash(pass),u=await one(`INSERT INTO users(id,email,password_hash,password_salt,name,role) VALUES($1,$2,$3,$4,$5,'owner') RETURNING *`,[id,email,h.hash,h.salt,String(x.name||'User')]);
   const co=await one(`INSERT INTO companies(id,name,owner_id) VALUES($1,$2,$3) RETURNING id,name,owner_id AS "ownerId",created_at AS "createdAt"`,[makeId('co'),String(x.companyName||'My Company'),u.id]);
   await q(`INSERT INTO company_members(company_id,user_id,role) VALUES($1,$2,'owner')`,[co.id,u.id]);
   const token=makeId('tok');sessions.set(token,{userId:u.id,companyId:co.id,role:'owner'});
   return send(res,201,{token,user:publicUser(u),companies:[{...co,role:'owner'}],companyId:co.id});
 }
 if(route==='login'&&req.method==='POST'){
   const x=await json(req),email=String(x.email||'').trim().toLowerCase(),u=await one('SELECT * FROM users WHERE email=$1',[email]);
   if(!u||!passwordVerify(String(x.password||''),u))return send(res,401,{error:'Invalid email or password'});
   const cs=await companiesFor(u.id);if(!cs.length)return send(res,403,{error:'No company assigned'});
   const token=makeId('tok');sessions.set(token,{userId:u.id,companyId:cs[0].id,role:cs[0].role});return send(res,200,{token,user:publicUser(u),companies:cs,companyId:cs[0].id});
 }
 const s=auth(req);if(!s)return send(res,401,{error:'Authentication required'});
 if(route==='logout'&&req.method==='POST'){const t=(req.headers.authorization||'').replace(/^Bearer\s+/,'');sessions.delete(t);return send(res,204,'')}
 if(route==='me'&&req.method==='GET'){const u=await one('SELECT * FROM users WHERE id=$1',[s.userId]),cs=await companiesFor(s.userId);return send(res,200,{user:publicUser(u),companies:cs,companyId:s.companyId})}
 if(route==='switch-company'&&req.method==='POST'){const x=await json(req);if(!await canCompany(s.userId,x.companyId))return send(res,403,{error:'Company access denied'});s.companyId=x.companyId;return send(res,200,{ok:true,companyId:s.companyId})}
 if(route==='companies'&&req.method==='POST'){const x=await json(req),co=await one(`INSERT INTO companies(id,name,owner_id) VALUES($1,$2,$3) RETURNING id,name,owner_id AS "ownerId",created_at AS "createdAt"`,[makeId('co'),String(x.name||'New Company'),s.userId]);await q(`INSERT INTO company_members(company_id,user_id,role) VALUES($1,$2,'owner')`,[co.id,s.userId]);return send(res,201,co)}
 if(route==='dashboard'&&req.method==='GET'){
   const sums=await one(`SELECT COALESCE(SUM(CASE WHEN kind='sales' THEN (payload->>'amount')::numeric ELSE 0 END),0) sales,COALESCE(SUM(CASE WHEN kind='purchases' THEN (payload->>'amount')::numeric ELSE 0 END),0) purchases,COALESCE(SUM(CASE WHEN kind='expenses' THEN (payload->>'amount')::numeric ELSE 0 END),0) expenses,COUNT(*) transactions FROM records WHERE company_id=$1`,[s.companyId]);
   const recent=(await q(`SELECT * FROM records WHERE company_id=$1 AND kind='sales' ORDER BY created_at DESC LIMIT 5`,[s.companyId])).map(rowToRecord);
   return send(res,200,{sales:Number(sums.sales),purchases:Number(sums.purchases),expenses:Number(sums.expenses),profit:Number(sums.sales)-Number(sums.purchases)-Number(sums.expenses),transactions:Number(sums.transactions),recentSales:recent});
 }
 const kinds=['sales','purchases','expenses','customers','suppliers','products'];
 if(kinds.includes(route)){
   if(req.method==='GET'){let rows=await q(`SELECT * FROM records WHERE company_id=$1 AND kind=$2 ORDER BY created_at DESC`,[s.companyId,route]);if(rid)rows=rows.filter(r=>r.id===rid);return send(res,200,rid?(rows[0]?rowToRecord(rows[0]):null):rows.map(rowToRecord))}
   if(req.method==='POST'){const x=await json(req),id=makeId(route.slice(0,-1)),r=await one(`INSERT INTO records(id,company_id,kind,payload,created_by) VALUES($1,$2,$3,$4::jsonb,$5) RETURNING *`,[id,s.companyId,route,JSON.stringify(x),s.userId]);return send(res,201,rowToRecord(r))}
   if(req.method==='PUT'&&rid){const x=await json(req),r=await one(`UPDATE records SET payload=$1::jsonb,updated_at=NOW() WHERE id=$2 AND company_id=$3 AND kind=$4 RETURNING *`,[JSON.stringify(x),rid,s.companyId,route]);return r?send(res,200,rowToRecord(r)):send(res,404,{error:'Record not found'})}
   if(req.method==='DELETE'&&rid){const r=await one(`DELETE FROM records WHERE id=$1 AND company_id=$2 AND kind=$3 RETURNING id`,[rid,s.companyId,route]);return r?send(res,204,''):send(res,404,{error:'Record not found'})}
 }
 if(route==='receipts'){
   if(req.method==='GET'){const rows=await q(`SELECT id,original_name AS "fileName",mime_type AS "mimeType",size_bytes AS "size",status,extracted,created_at AS "createdAt" FROM receipts WHERE company_id=$1 ORDER BY created_at DESC`,[s.companyId]);return send(res,200,rows)}
   if(req.method==='POST'){return upload.single('file')(req,res,async err=>{try{if(err)throw err;if(!req.file)throw Error('Receipt file is required');const cfg=s3Config();if(!cfg.bucket)throw Error('Persistent S3 object storage is not configured');const key=`companies/${s.companyId}/receipts/${makeId('receipt')}-${req.file.originalname.replace(/[^a-zA-Z0-9._-]/g,'_')}`;await s3().send(new PutObjectCommand({Bucket:cfg.bucket,Key:key,Body:req.file.buffer,ContentType:req.file.mimetype,Metadata:{companyId:s.companyId,uploadedBy:s.userId}}));const r=await one(`INSERT INTO receipts(id,company_id,original_name,mime_type,size_bytes,object_key,created_by) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,original_name AS "fileName",mime_type AS "mimeType",size_bytes AS "size",status,created_at AS "createdAt"`,[makeId('rec'),s.companyId,req.file.originalname,req.file.mimetype,req.file.size,key,s.userId]);send(res,201,r)}catch(e){send(res,400,{error:e.message})}})}
   if(req.method==='GET'&&rid){const r=await one(`SELECT * FROM receipts WHERE id=$1 AND company_id=$2`,[rid,s.companyId]);if(!r)return send(res,404,{error:'Receipt not found'});const cfg=s3Config();const obj=await s3().send(new GetObjectCommand({Bucket:cfg.bucket,Key:r.object_key}));res.writeHead(200,{'Content-Type':r.mime_type,'Content-Disposition':`inline; filename="${r.original_name.replace(/"/g,'') }"`});return obj.Body.pipe(res)}
   if(req.method==='DELETE'&&rid){const r=await one(`DELETE FROM receipts WHERE id=$1 AND company_id=$2 RETURNING *`,[rid,s.companyId]);if(!r)return send(res,404,{error:'Receipt not found'});try{await s3().send(new DeleteObjectCommand({Bucket:s3Config().bucket,Key:r.object_key}))}catch(e){console.error('S3 delete failed',e.message)}return send(res,204,'')}
 }
 return send(res,404,{error:'Unknown endpoint'});
}
function serve(req,res){let p=decodeURIComponent(new URL(req.url,'http://x').pathname);if(p==='/')p='/index.html';const f=path.normalize(path.join(PUBLIC,p));if(!f.startsWith(PUBLIC))return send(res,403,{error:'Forbidden'});fs.readFile(f,(e,b)=>{if(e)return send(res,404,{error:'Not found'});const ext=path.extname(f).slice(1);res.writeHead(200,{'Content-Type':ext==='html'?'text/html; charset=utf-8':ext==='js'?'text/javascript; charset=utf-8':ext==='css'?'text/css':'application/octet-stream','Cache-Control':'no-cache'});res.end(b)})}
(async()=>{try{await migrate();http.createServer(async(req,res)=>{try{const u=new URL(req.url,'http://x');if(u.pathname.startsWith('/api/'))return api(req,res,u);if(req.method==='GET')return serve(req,res);send(res,405,{error:'Method not allowed'})}catch(e){console.error(e);send(res,500,{error:'Internal server error'})}}).listen(PORT,()=>console.log(`Acoot Smart Books v4 listening on ${PORT}`))}catch(e){console.error('Startup failed:',e);process.exit(1)}})();
