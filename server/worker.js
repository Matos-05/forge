// FORGE – serveur Cloudflare : app (depuis GitHub) + comptes + synchronisation par utilisateur
const RAW="https://raw.githubusercontent.com/Matos-05/forge/main";
const TYPES={html:"text/html; charset=utf-8",js:"text/javascript; charset=utf-8",webmanifest:"application/manifest+json",png:"image/png"};
const FILES=new Set(["/index.html","/sw.js","/manifest.webmanifest","/icon-180.png","/icon-192.png","/icon-512.png"]);
const CORS={"Access-Control-Allow-Origin":"*","Access-Control-Allow-Headers":"authorization,content-type","Access-Control-Allow-Methods":"GET,POST,OPTIONS"};
const json=(o,s=200)=>new Response(JSON.stringify(o),{status:s,headers:{...CORS,"content-type":"application/json","cache-control":"no-store"}});
const enc=new TextEncoder();
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("");
const rnd=n=>hex(crypto.getRandomValues(new Uint8Array(n)));
const sha=async s=>hex(await crypto.subtle.digest("SHA-256",enc.encode(s)));
async function pbkdf2(pw,salt){const k=await crypto.subtle.importKey("raw",enc.encode(pw),"PBKDF2",false,["deriveBits"]);return hex(await crypto.subtle.deriveBits({name:"PBKDF2",salt:enc.encode(salt),iterations:100000,hash:"SHA-256"},k,256))}
function safeEq(a,b){if(typeof a!=="string"||typeof b!=="string"||a.length!==b.length)return false;let r=0;for(let i=0;i<a.length;i++)r|=a.charCodeAt(i)^b.charCodeAt(i);return r===0}
const normEmail=e=>String(e||"").trim().toLowerCase();
const okEmail=e=>/^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/.test(e);
async function newSession(env,uid){const tok=rnd(32);const now=Date.now();await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,created_at,expires_at) VALUES(?1,?2,?3,?4)").bind(await sha(tok),uid,now,now+90*864e5).run();return tok}
async function auth(req,env){const t=(req.headers.get("authorization")||"").replace(/^Bearer\s+/i,"").trim();if(!t||t.length!==64)return null;
 const r=await env.DB.prepare("SELECT s.user_id AS id,u.email AS email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?1 AND s.expires_at>?2").bind(await sha(t),Date.now()).first();return r||null}
async function locked(env,key){const r=await env.DB.prepare("SELECT count,until FROM attempts WHERE key=?1").bind(key).first();return r&&r.until>Date.now()}
async function fail(env,key){const r=await env.DB.prepare("SELECT count FROM attempts WHERE key=?1").bind(key).first();const c=(r?r.count:0)+1;const until=c>=5?Date.now()+15*60000:0;
 await env.DB.prepare("INSERT INTO attempts(key,count,until) VALUES(?1,?2,?3) ON CONFLICT(key) DO UPDATE SET count=?2,until=?3").bind(key,c>=5?0:c,until).run()}
async function clearFail(env,key){await env.DB.prepare("DELETE FROM attempts WHERE key=?1").bind(key).run()}
export default {async fetch(req,env){
 const url=new URL(req.url);const p=url.pathname;
 if(p.startsWith("/api/")){
  if(req.method==="OPTIONS")return new Response(null,{headers:CORS});
  let body={};if(req.method==="POST"){try{body=await req.json()}catch(e){return json({error:"bad_json"},400)}}
  if(p==="/api/signup"){
   const email=normEmail(body.email),pw=String(body.password||"");
   if(!safeEq(String(body.invite||"").trim().toUpperCase(),env.INVITE))return json({error:"invite"},403);
   if(!okEmail(email))return json({error:"email"},400);if(pw.length<8||pw.length>200)return json({error:"password"},400);
   if(await env.DB.prepare("SELECT 1 FROM users WHERE email=?1").bind(email).first())return json({error:"exists"},409);
   const id="u_"+rnd(8),salt=rnd(16);await env.DB.prepare("INSERT INTO users(id,email,pass_hash,salt,created_at) VALUES(?1,?2,?3,?4,?5)").bind(id,email,await pbkdf2(pw,salt),salt,Date.now()).run();
   return json({token:await newSession(env,id),email,id})}
  if(p==="/api/login"){
   const email=normEmail(body.email),pw=String(body.password||"");const key="login:"+email;
   if(await locked(env,key))return json({error:"locked"},429);
   const u=await env.DB.prepare("SELECT id,pass_hash,salt FROM users WHERE email=?1").bind(email).first();
   if(!u||!safeEq(await pbkdf2(pw,u.salt),u.pass_hash)){await fail(env,key);return json({error:"credentials"},401)}
   await clearFail(env,key);return json({token:await newSession(env,u.id),email,id:u.id})}
  // Transition : anciennes versions de l'app (code de synchro unique) -> table docs
  const bearer=(req.headers.get("authorization")||"").replace(/^Bearer\s+/i,"").trim();
  if(p==="/api/sync"&&env.TOKEN&&safeEq(bearer.toUpperCase(),env.TOKEN)){
   const now=Date.now();const docs=Array.isArray(body.docs)?body.docs.slice(0,500):[];const st=[];
   for(const d of docs){if(typeof d.path!=="string"||!/^[A-Za-z0-9_\-\/.:]{1,200}$/.test(d.path))continue;const s=JSON.stringify(d.data===undefined?null:d.data);if(s.length>256000)continue;const ua=Math.min(Number(d.updatedAt)||now,now+60000);
    st.push(env.DB.prepare("INSERT INTO docs(path,data,updated_at,deleted,srv) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(path) DO UPDATE SET data=excluded.data,updated_at=excluded.updated_at,deleted=excluded.deleted,srv=excluded.srv WHERE excluded.updated_at>docs.updated_at").bind(d.path,s,ua,d.deleted?1:0,now))}
   if(st.length)await env.DB.batch(st);
   const {results}=await env.DB.prepare("SELECT path,data,updated_at,deleted FROM docs WHERE srv>?1 ORDER BY srv LIMIT 3000").bind(Number(body.since)||0).all();
   return json({now,docs:results.map(r=>({path:r.path,data:JSON.parse(r.data),updatedAt:r.updated_at,deleted:!!r.deleted}))})}
  const me=await auth(req,env);if(!me)return json({error:"unauthorized"},401);
  if(p==="/api/me")return json({email:me.email,id:me.id});
  if(p==="/api/logout"){const t=(req.headers.get("authorization")||"").replace(/^Bearer\s+/i,"").trim();await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?1").bind(await sha(t)).run();return json({ok:true})}
  if(p==="/api/password"&&req.method==="POST"){const pw=String(body.newPassword||"");if(pw.length<8||pw.length>200)return json({error:"password"},400);
   const u=await env.DB.prepare("SELECT pass_hash,salt FROM users WHERE id=?1").bind(me.id).first();if(!safeEq(await pbkdf2(String(body.oldPassword||""),u.salt),u.pass_hash))return json({error:"credentials"},401);
   const salt=rnd(16);await env.DB.prepare("UPDATE users SET pass_hash=?1,salt=?2 WHERE id=?3").bind(await pbkdf2(pw,salt),salt,me.id).run();return json({ok:true})}
  if(p==="/api/claim"&&req.method==="POST"){
   if(!safeEq(String(body.legacy||"").trim().toUpperCase(),env.TOKEN))return json({error:"legacy"},403);
   const done=await env.DB.prepare("SELECT 1 FROM udocs WHERE user_id=?1 LIMIT 1").bind(me.id).first();
   const now=Date.now();await env.DB.prepare("INSERT OR IGNORE INTO udocs(user_id,path,data,updated_at,deleted,srv) SELECT ?1,path,data,updated_at,deleted,?2 FROM docs").bind(me.id,now).run();
   return json({ok:true,already:!!done})}
  if(p==="/api/delete-account"&&req.method==="POST"){
   const u=await env.DB.prepare("SELECT pass_hash,salt FROM users WHERE id=?1").bind(me.id).first();if(!safeEq(await pbkdf2(String(body.password||""),u.salt),u.pass_hash))return json({error:"credentials"},401);
   await env.DB.batch([env.DB.prepare("DELETE FROM udocs WHERE user_id=?1").bind(me.id),env.DB.prepare("DELETE FROM sessions WHERE user_id=?1").bind(me.id),env.DB.prepare("DELETE FROM users WHERE id=?1").bind(me.id)]);return json({ok:true})}
  if(p==="/api/sync"&&req.method==="POST"){
   const now=Date.now();const docs=Array.isArray(body.docs)?body.docs.slice(0,500):[];const st=[];
   for(const d of docs){if(typeof d.path!=="string"||!/^[A-Za-z0-9_\-\/.:]{1,200}$/.test(d.path))continue;const s=JSON.stringify(d.data===undefined?null:d.data);if(s.length>256000)continue;
    const ua=Math.min(Number(d.updatedAt)||now,now+60000);
    st.push(env.DB.prepare("INSERT INTO udocs(user_id,path,data,updated_at,deleted,srv) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(user_id,path) DO UPDATE SET data=excluded.data,updated_at=excluded.updated_at,deleted=excluded.deleted,srv=excluded.srv WHERE excluded.updated_at>udocs.updated_at").bind(me.id,d.path,s,ua,d.deleted?1:0,now))}
   if(st.length)await env.DB.batch(st);
   const since=Number(body.since)||0;
   const {results}=await env.DB.prepare("SELECT path,data,updated_at,deleted FROM udocs WHERE user_id=?1 AND srv>?2 ORDER BY srv LIMIT 3000").bind(me.id,since).all();
   return json({now,docs:results.map(r=>({path:r.path,data:JSON.parse(r.data),updatedAt:r.updated_at,deleted:!!r.deleted}))})}
  return json({error:"not_found"},404);
 }
 let q=p;if(q==="/")q="/index.html";
 if(!FILES.has(q)){if((req.headers.get("accept")||"").includes("text/html"))q="/index.html";else return new Response("Not found",{status:404})}
 const r=await fetch(RAW+q,{cf:{cacheTtl:60,cacheEverything:true}});
 if(!r.ok)return new Response("FORGE : app momentanément indisponible ("+r.status+")",{status:502,headers:{"content-type":"text/plain; charset=utf-8"}});
 const ext=q.split(".").pop();
 return new Response(r.body,{headers:{"content-type":TYPES[ext]||"application/octet-stream","cache-control":(q==="/sw.js"||q==="/index.html")?"no-cache":"public, max-age=3600","x-content-type-options":"nosniff"}});
}};
