#!/usr/bin/env node
/*
  CRYPT BRAWL MATCHMAKER  (zero dependencies, Node 14+)

  What it does
    - Matchmaking: pairs players who press PLAY > MATCHMAKING, first come first served.
    - Private servers: PLAY > PRIVATE SERVER > CREATE gives a 4-letter code; a friend enters it under JOIN.
    - Relays the WebRTC handshake between the two paired players, then forgets them.
      The match itself is peer-to-peer: no game traffic ever passes through this server.

  Run it
    node matchmaker-server.js                 (listens on PORT or 8787)
    PORT=3000 node matchmaker-server.js

  Put it online (any host that runs Node works: Render, Railway, Fly.io, a VPS...)
    Start command:  node matchmaker-server.js
    Then, in the game: PLAY > SERVER SETTINGS and paste the address, e.g. https://crypt-brawl.onrender.com
    If the game page is served over https, the matchmaker must be https as well (hosts like Render give you this).
*/
const http=require('http'),crypto=require('crypto');
const PORT=+process.env.PORT||8787;
const T=new Map();            // ticket id -> ticket
const Q=[];                   // ticket ids waiting for a random opponent
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
 send(a,{t:'matched',role:'host'});send(b,{t:'matched',role:'guest'})}
function tryMM(){
 const live=Q.map(id=>T.get(id)).filter(t=>t&&t.res&&!t.peer);
 while(live.length>=2)match(live.shift(),live.shift());
 stats()}
function stats(){const n=Q.length,online=T.size;for(const id of Q){const t=T.get(id);if(t)send(t,{t:'q',n,online})}}
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
 if(((n/2000)|0)%5===0)for(const t of T.values())if(t.res)try{t.res.write(': ping\n\n')}catch(e){}
 stats()},2000).unref?.();
function body(req){return new Promise((ok,no)=>{let s='';req.on('data',c=>{s+=c;if(s.length>65536){no(new Error('too big'));req.destroy()}});req.on('end',()=>{try{ok(s?JSON.parse(s):{})}catch(e){ok({})}});req.on('error',no)})}
function json(res,code,o){res.writeHead(code,{'Content-Type':'application/json'});res.end(JSON.stringify(o))}
const srv=http.createServer(async(req,res)=>{
 res.setHeader('Access-Control-Allow-Origin','*');res.setHeader('Access-Control-Allow-Headers','Content-Type');res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');
 if(req.method==='OPTIONS'){res.writeHead(204);return res.end()}
 const u=new URL(req.url,'http://x'),p=u.pathname;
 try{
  if(req.method==='GET'&&p==='/health')return json(res,200,{ok:1,game:'crypt-brawl',queued:Q.length,online:T.size,servers:R.size});
  if(req.method==='GET'&&p==='/'){res.writeHead(200,{'Content-Type':'text/plain'});return res.end('Crypt Brawl matchmaker is running.\nPlayers online: '+T.size+', searching: '+Q.length+'\n')}
  if(req.method==='POST'&&p==='/ticket'){
   const b=await body(req),mode=b.mode;
   if(!['mm','create','join'].includes(mode))return json(res,400,{error:'bad mode'});
   if(T.size>5000)return json(res,503,{error:'The server is full, try again soon.'});
   const t={id:rid(),mode,res:null,box:[],peer:null,born:now(),gone:0,done:false,code:'',at:0};
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
 }catch(e){try{json(res,500,{error:'server error'})}catch(e2){}}});
srv.listen(PORT,()=>console.log('Crypt Brawl matchmaker listening on port '+PORT));
module.exports=srv;
