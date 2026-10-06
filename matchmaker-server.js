#!/usr/bin/env node
/*
  CRYPT BRAWL MATCHMAKER  (no npm packages needed, Node 18 or newer)

  What it does
    - Matchmaking: pairs players who press PLAY > QUICK MATCH, first come first served.
    - Ranked matchmaking: signed-in players are paired by skill (rating), and wins/losses change their rating.
    - Accounts: username + password. Passwords are stored only as salted scrypt hashes.
    - Private servers: PLAY > PRIVATE SERVER > CREATE gives a 4-letter code; a friend enters it under JOIN.
    - Relays the WebRTC handshake between the two paired players, then forgets them.
      The match itself is peer-to-peer: no game traffic ever passes through this server.

  Where accounts are saved
    Set these three environment variables and accounts are saved in a free Upstash Redis database:
      UPSTASH_REDIS_REST_URL     (from the Upstash dashboard, "REST API" section)
      UPSTASH_REDIS_REST_TOKEN   (same place)
      AUTH_SECRET                (any long random text you make up; keeps login sessions valid across restarts)
    Without them the server still runs, but accounts live only in memory and are LOST on every restart.
    (Fine for testing on your own computer, not for a real launch.)

  Run it
    node matchmaker-server.js                 (listens on PORT or 8787)
    PORT=3000 node matchmaker-server.js
*/
const http=require('http'),crypto=require('crypto'),util=require('util');
const scrypt=util.promisify(crypto.scrypt);
const PORT=+process.env.PORT||8787;
const REDIS_URL=(process.env.UPSTASH_REDIS_REST_URL||'').trim().replace(/\/+$/,''),REDIS_TOKEN=(process.env.UPSTASH_REDIS_REST_TOKEN||'').trim();
const SECRET=process.env.AUTH_SECRET||crypto.randomBytes(32).toString('hex');
const WSTEP=+process.env.CB_WSTEP||5000;            // ranked search widens every WSTEP ms
const REPORT_WAIT=+process.env.CB_REPORT_WAIT||75000; // a lone result report is accepted after this long
const START_RATING=1000;
const REG_LIMIT=+process.env.CB_REG_LIMIT||8;        // accounts one connection may create per hour

// ------------------------------------------------------------------ storage
function memDb(){
 const kv=new Map(),z=new Map();
 const exp=(k)=>{const e=kv.get(k);if(e&&e.x&&e.x<Date.now()){kv.delete(k);return null}return e};
 return{kind:'memory',
  async get(k){const e=exp(k);return e?JSON.parse(e.v):null},
  async set(k,o,ex){kv.set(k,{v:JSON.stringify(o),x:ex?Date.now()+ex*1000:0})},
  async setnx(k,o,ex){if(exp(k))return false;kv.set(k,{v:JSON.stringify(o),x:ex?Date.now()+ex*1000:0});return true},
  async zset(n,m,s){if(!z.has(n))z.set(n,new Map());z.get(n).set(m,s)},
  async ztop(n,c){const a=[...(z.get(n)||new Map())].sort((x,y)=>y[1]-x[1]).slice(0,c);return a.map(([name,r])=>({name,rating:Math.round(r)}))},
  async zrank(n,m){const a=[...(z.get(n)||new Map())].sort((x,y)=>y[1]-x[1]);const i=a.findIndex(e=>e[0]===m);return i<0?null:i+1}}}
function redisDb(){
 async function cmd(args){
  const r=await fetch(REDIS_URL,{method:'POST',headers:{Authorization:'Bearer '+REDIS_TOKEN,'Content-Type':'application/json'},body:JSON.stringify(args)});
  const j=await r.json().catch(()=>({}));
  if(!r.ok||j.error)throw new Error(j.error||('database error '+r.status));
  return j.result}
 return{kind:'upstash',
  async get(k){const v=await cmd(['GET',k]);return v==null?null:JSON.parse(v)},
  async set(k,o,ex){await cmd(ex?['SET',k,JSON.stringify(o),'EX',String(ex)]:['SET',k,JSON.stringify(o)])},
  async setnx(k,o,ex){return(await cmd(ex?['SET',k,JSON.stringify(o),'NX','EX',String(ex)]:['SET',k,JSON.stringify(o),'NX']))==='OK'},
  async zset(n,m,s){await cmd(['ZADD',n,String(s),m])},
  async ztop(n,c){const a=await cmd(['ZREVRANGE',n,'0',String(c-1),'WITHSCORES']),o=[];for(let i=0;i+1<a.length;i+=2)o.push({name:a[i],rating:Math.round(+a[i+1])});return o},
  async zrank(n,m){const r=await cmd(['ZREVRANK',n,m]);return r==null?null:+r+1}}}
const db=REDIS_URL&&REDIS_TOKEN?redisDb():memDb();
if(db.kind==='memory')console.log('WARNING: no database configured (UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN). Accounts are kept in memory and will be lost on restart.');
else console.log('Accounts are saved in Upstash Redis.');
if(!process.env.AUTH_SECRET)console.log('WARNING: AUTH_SECRET is not set. Logins will stop working every time the server restarts.');

// ------------------------------------------------------------------ accounts
const NAME_RE=/^[A-Za-z0-9_]{3,16}$/,RESERVED=new Set(['guest','admin','administrator','moderator','mod','cpu','system','server','crypt_brawl']);
const hits=new Map();
function limited(key,max,ms){const n=Date.now(),a=(hits.get(key)||[]).filter(t=>n-t<ms);a.push(n);hits.set(key,a);return a.length>max}
const b64u=b=>Buffer.from(b).toString('base64url');
function mkTok(name){const p=b64u(JSON.stringify({u:name,e:Date.now()+30*864e5})),s=crypto.createHmac('sha256',SECRET).update(p).digest('base64url');return p+'.'+s}
function readTok(tok){
 try{const[p,s]=String(tok||'').split('.');if(!p||!s)return null;
  const want=crypto.createHmac('sha256',SECRET).update(p).digest('base64url');
  const a=Buffer.from(s),b=Buffer.from(want);if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return null;
  const o=JSON.parse(Buffer.from(p,'base64url').toString());if(!o||!o.u||o.e<Date.now())return null;return o.u}catch(e){return null}}
const ukey=n=>'u:'+String(n).toLowerCase();
const profile=u=>({name:u.n,rating:u.r,games:u.g,wins:u.w,losses:u.l});
async function userFromTok(tok){const n=readTok(tok);if(!n)return null;return db.get(ukey(n))}
async function hashPw(pw,salt){return(await scrypt(pw,salt,32)).toString('hex')}
const clientIp=req=>String(req.headers['x-forwarded-for']||req.socket.remoteAddress||'').split(',')[0].trim();
function fail(code,msg){return Object.assign(new Error(msg),{code})}

async function register(req,b){
 const name=String(b.name||'').trim(),pw=String(b.pass||'');
 if(!NAME_RE.test(name))throw fail(400,'Names are 3 to 16 characters: letters, numbers and _ only.');
 if(RESERVED.has(name.toLowerCase()))throw fail(400,'That name is reserved.');
 if(pw.length<6||pw.length>64)throw fail(400,'Passwords need 6 to 64 characters.');
 if(limited('reg:'+clientIp(req),REG_LIMIT,3600000))throw fail(429,'Too many accounts created from this connection. Try again later.');
 const salt=crypto.randomBytes(16).toString('hex'),u={n:name,s:salt,h:await hashPw(pw,salt),r:START_RATING,g:0,w:0,l:0,c:Date.now()};
 if(!(await db.setnx(ukey(name),u)))throw fail(409,'That name is taken. Try another.');
 await db.zset('lb',name,u.r);
 return{token:mkTok(name),profile:profile(u)}}
async function login(req,b){
 const name=String(b.name||'').trim(),pw=String(b.pass||'');
 if(limited('li:'+clientIp(req),30,600000)||limited('ln:'+name.toLowerCase(),8,600000))throw fail(429,'Too many tries. Wait a few minutes and try again.');
 if(!NAME_RE.test(name)||!pw||pw.length>64)throw fail(401,'Wrong name or password.');
 const u=await db.get(ukey(name));
 const salt=u?u.s:'00000000000000000000000000000000',h=await hashPw(pw,salt);
 if(!u||h.length!==u.h.length||!crypto.timingSafeEqual(Buffer.from(h),Buffer.from(u.h)))throw fail(401,'Wrong name or password.');
 return{token:mkTok(u.n),profile:profile(u)}}
async function me(b){
 const u=await userFromTok(b.token);if(!u)throw fail(401,'Please sign in again.');
 const rank=await db.zrank('lb',u.n);return{profile:{...profile(u),rank:rank||0}}}
let lbCache={t:0,v:[]};
async function leaderboard(){if(Date.now()-lbCache.t<8000)return lbCache.v;const v=await db.ztop('lb',20);lbCache={t:Date.now(),v};return v}

// ------------------------------------------------------------------ ranked results
function elo(ra,rb,aWon,ga,gb){
 const ea=1/(1+Math.pow(10,(rb-ra)/400)),eb=1-ea,ka=ga<10?40:24,kb=gb<10?40:24;
 return{a:Math.max(100,Math.round(ra+ka*((aWon?1:0)-ea))),b:Math.max(100,Math.round(rb+kb*((aWon?0:1)-eb)))}}
async function applyResult(m,aWon){
 const ua=await db.get(ukey(m.a.n)),ub=await db.get(ukey(m.b.n));
 if(!ua||!ub)return null;
 const r=elo(ua.r,ub.r,aWon,ua.g,ub.g),da=r.a-ua.r,dbb=r.b-ub.r;
 ua.r=r.a;ub.r=r.b;ua.g++;ub.g++;if(aWon){ua.w++;ub.l++}else{ub.w++;ua.l++}
 await db.set(ukey(m.a.n),ua);await db.set(ukey(m.b.n),ub);
 await db.zset('lb',ua.n,ua.r);await db.zset('lb',ub.n,ub.r);lbCache.t=0;
 return{a:{rating:ua.r,delta:da},b:{rating:ub.r,delta:dbb}}}
const sk=(id,round)=>id+':'+round;
async function resolve(id,round,side,m){
 const k=sk(id,round);
 let res=await db.get('rs:'+k);
 if(!res){
  const ra=await db.get('rp:'+k+':a'),rb=await db.get('rp:'+k+':b');
  let winner=null,decided=false;
  if(ra&&rb){decided=true;if(ra.w!==rb.w)winner=ra.w?'a':'b'}
  else if(ra||rb){
   const r=ra||rb,from=ra?'a':'b';
   if(Date.now()-r.t>=REPORT_WAIT){decided=true;winner=r.w?from:(from==='a'?'b':'a')}}
  if(decided){
   if(await db.setnx('rl:'+k,1,86400)){
    res=winner?await applyResult(m,winner==='a'):null;
    res=res?{w:winner,a:res.a,b:res.b}:{w:null};
    await db.set('rs:'+k,res,86400)}
   else res=await db.get('rs:'+k)}}
 if(!res)return{done:false};
 if(!res.w)return{done:true,void:true};
 const mine=res[side];return{done:true,win:res.w===side,delta:mine.delta,rating:mine.rating}}
async function report(b){
 const u=await userFromTok(b.token);if(!u)throw fail(401,'Please sign in again.');
 const id=String(b.match||'').slice(0,40),round=Math.max(0,Math.min(99,parseInt(b.round)||0));
 const m=await db.get('m:'+id);if(!m)throw fail(404,'Unknown match.');
 const side=m.a.n.toLowerCase()===u.n.toLowerCase()?'a':m.b.n.toLowerCase()===u.n.toLowerCase()?'b':null;
 if(!side)throw fail(403,'You were not in this match.');
 await db.setnx('rp:'+sk(id,round)+':'+side,{w:!!b.win,t:Date.now()},86400);
 const first=await resolve(id,round,side,m);
 if(!first.done){ // make sure a lone report still gets settled even if the other player never answers
  setTimeout(()=>resolve(id,round,side,m).catch(()=>{}),REPORT_WAIT+500).unref?.()}
 return first}

// ------------------------------------------------------------------ matchmaking
const T=new Map();            // ticket id -> ticket
const Q=[];                   // ticket ids waiting for an opponent
const R=new Map();            // private server code -> host ticket id
const ALPHA='ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const rid=()=>crypto.randomBytes(9).toString('hex');
const now=()=>Date.now();
function newCode(){for(let k=0;k<60;k++){let c='';for(let i=0;i<4;i++)c+=ALPHA[crypto.randomInt(ALPHA.length)];if(!R.has(c))return c}return null}
function send(t,o){if(t.res&&!t.res.writableEnded){try{t.res.write('data: '+JSON.stringify(o)+'\n\n')}catch(e){t.res=null;t.gone=now();t.box.push(o)}}else t.box.push(o)}
function unqueue(t){const i=Q.indexOf(t.id);if(i>=0)Q.splice(i,1);if(t.code&&R.get(t.code)===t.id)R.delete(t.code)}
function drop(t,notify){
 if(!T.has(t.id))return;T.delete(t.id);unqueue(t);
 if(t.res){try{t.res.end()}catch(e){}t.res=null}
 const p=t.peer&&T.get(t.peer);if(p&&notify&&!t.done&&!p.done)send(p,{t:'left'})}
function match(a,b){
 unqueue(a);unqueue(b);a.peer=b.id;b.peer=a.id;a.at=b.at=now();
 let mid='',oa=null,ob=null;
 if(a.user&&b.user){
  mid=rid();oa={name:b.user.n,rating:b.user.r};ob={name:a.user.n,rating:a.user.r};
  db.set('m:'+mid,{a:{n:a.user.n,r:a.user.r},b:{n:b.user.n,r:b.user.r},t:now()},86400).catch(e=>console.log('match save failed',e.message))}
 send(a,{t:'matched',role:'host',match:mid,opp:oa});send(b,{t:'matched',role:'guest',match:mid,opp:ob})}
const win=t=>{const w=(now()-t.qt)/WSTEP;return w>=9?1e9:150+Math.floor(w)*75}   // rating range grows while you wait, anyone after ~9 steps
function tryMM(){
 const live=Q.map(id=>T.get(id)).filter(t=>t&&t.res&&!t.peer);
 const casual=live.filter(t=>!t.user);
 while(casual.length>=2)match(casual.shift(),casual.shift());
 const ranked=live.filter(t=>t.user).sort((x,y)=>x.qt-y.qt);
 for(const a of ranked){
  if(a.peer)continue;
  let best=null,bd=1e9;
  for(const b of ranked){
   if(b===a||b.peer||b.user.n.toLowerCase()===a.user.n.toLowerCase())continue;
   const d=Math.abs(a.user.r-b.user.r);
   if(d<=Math.max(win(a),win(b))&&d<bd){best=b;bd=d}}
  if(best)match(a,best)}
 stats()}
function stats(){
 const online=T.size,nr=Q.filter(id=>{const t=T.get(id);return t&&t.user}).length,nc=Q.length-nr;
 for(const id of Q){const t=T.get(id);if(t)send(t,t.user?{t:'q',n:nr,online,w:Math.min(win(t),9999),r:t.user.r}:{t:'q',n:nc,online})}}
function onStream(t){
 t.box.splice(0).forEach(o=>send(t,o));
 if(t.peer)return;
 if(t.mode==='mm')tryMM();
 else if(t.mode==='join'){
  const h=T.get(R.get(t.code));
  if(h&&h.res&&!h.peer)match(h,t);else{send(t,{t:'error',m:'That server is no longer available.'});drop(t,false)}}
 else send(t,{t:'q',n:0,online:T.size})}
setInterval(()=>{ // housekeeping
 const n=now();
 for(const t of [...T.values()]){
  if(!t.res&&n-(t.gone||t.born)>(t.peer?6000:25000))drop(t,true);                  // never connected / closed the tab (6s lets a brief reconnect through)
  else if(t.peer&&n-t.at>180000)drop(t,false);                                       // handshake should take seconds
  else if(!t.peer&&t.mode==='create'&&n-t.born>3600000)drop(t,false)}                // idle private server
 for(const[k,a]of hits){const f=a.filter(x=>n-x<3600000);if(f.length)hits.set(k,f);else hits.delete(k)}
 if(((n/2000)|0)%5===0)for(const t of T.values())if(t.res)try{t.res.write(': ping\n\n')}catch(e){}
 tryMM()},2000).unref?.();

// ------------------------------------------------------------------ http
function body(req){return new Promise((ok,no)=>{let s='';req.on('data',c=>{s+=c;if(s.length>65536){no(new Error('too big'));req.destroy()}});req.on('end',()=>{try{ok(s?JSON.parse(s):{})}catch(e){ok({})}});req.on('error',no)})}
function json(res,code,o){res.writeHead(code,{'Content-Type':'application/json'});res.end(JSON.stringify(o))}
const srv=http.createServer(async(req,res)=>{
 res.setHeader('Access-Control-Allow-Origin','*');res.setHeader('Access-Control-Allow-Headers','Content-Type');res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');
 if(req.method==='OPTIONS'){res.writeHead(204);return res.end()}
 const u=new URL(req.url,'http://x'),p=u.pathname;
 try{
  if(req.method==='GET'&&p==='/health')return json(res,200,{ok:1,game:'crypt-brawl',queued:Q.length,online:T.size,servers:R.size,accounts:db.kind});
  if(req.method==='GET'&&p==='/'){res.writeHead(200,{'Content-Type':'text/plain'});return res.end('Crypt Brawl matchmaker is running.\nPlayers online: '+T.size+', searching: '+Q.length+'\nAccounts: '+db.kind+'\n')}
  if(req.method==='GET'&&p==='/leaderboard')return json(res,200,{top:await leaderboard()});
  if(req.method==='POST'&&p==='/register')return json(res,200,await register(req,await body(req)));
  if(req.method==='POST'&&p==='/login')return json(res,200,await login(req,await body(req)));
  if(req.method==='POST'&&p==='/me')return json(res,200,await me(await body(req)));
  if(req.method==='POST'&&p==='/report')return json(res,200,await report(await body(req)));
  if(req.method==='POST'&&p==='/ticket'){
   const b=await body(req),mode=b.mode;
   if(!['mm','create','join'].includes(mode))return json(res,400,{error:'bad mode'});
   if(T.size>5000)return json(res,503,{error:'The server is full, try again soon.'});
   const t={id:rid(),mode,res:null,box:[],peer:null,born:now(),qt:now(),gone:0,done:false,code:'',at:0,user:null};
   if(mode==='mm'&&b.ranked){
    const usr=await userFromTok(b.token);if(!usr)return json(res,401,{error:'Please sign in to play ranked.'});
    for(const id of Q){const o=T.get(id);if(o&&o.user&&o.user.n.toLowerCase()===usr.n.toLowerCase())drop(o,false)}   // one search per account
    t.user=usr}
   if(mode==='create'){t.code=newCode();if(!t.code)return json(res,503,{error:'No free server codes.'});R.set(t.code,t.id)}
   if(mode==='join'){
    const c=String(b.code||'').toUpperCase().replace(/[^A-Z0-9]/g,''),h=T.get(R.get(c));
    if(!h||h.peer)return json(res,404,{error:'No server with that code. Check it and try again.'});
    t.code=c}
   if(mode==='mm')Q.push(t.id);
   T.set(t.id,t);return json(res,200,{id:t.id,code:mode==='create'?t.code:undefined})}
  if(req.method==='GET'&&p==='/events'){
   const t=T.get(u.searchParams.get('id'));if(!t)return json(res,404,{error:'unknown ticket'});
   res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-cache, no-transform','Connection':'keep-alive','X-Accel-Buffering':'no'});
   res.write('retry: 3000\n\n');
   if(t.res)try{t.res.end()}catch(e){}
   t.res=res;t.gone=0;
   req.on('close',()=>{if(t.res===res){t.res=null;t.gone=now()}});
   return onStream(t)}
  if(req.method==='POST'&&p==='/signal'){
   const b=await body(req),t=T.get(b.id),q=t&&t.peer&&T.get(t.peer);
   if(!q)return json(res,404,{error:'no partner'});
   send(q,{t:'sig',d:b.d});return json(res,200,{ok:1})}
  if(req.method==='POST'&&p==='/leave'){
   const b=await body(req),t=T.get(b.id);if(t){if(b.done)t.done=true;drop(t,true)}
   return json(res,200,{ok:1})}
  json(res,404,{error:'not found'})
 }catch(e){
  if(e&&e.code&&typeof e.code==='number')return json(res,e.code,{error:e.message});
  console.log('error on',req.method,p,e&&e.message);
  try{json(res,503,{error:'Accounts are temporarily unavailable. Try again in a moment.'})}catch(e2){}}});
process.on('unhandledRejection',e=>console.log('unhandled',e&&e.message));
srv.listen(PORT,()=>console.log('Crypt Brawl matchmaker listening on port '+PORT));
module.exports=srv;
