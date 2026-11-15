import {createServer} from 'node:http';
import {createHmac,randomBytes,timingSafeEqual} from 'node:crypto';
import {createReadStream} from 'node:fs';
import {mkdir,stat} from 'node:fs/promises';
import {dirname,extname,resolve,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {DatabaseSync} from 'node:sqlite';
import {replay,score,RATE} from '../christmas/engine.mjs';

const root=fileURLToPath(new URL('../',import.meta.url));
const base='/api/kombucha/';
const port=Number(process.env.PORT||8787);
const local=process.env.HOST||'127.0.0.1';
const origin=process.env.GAME_ORIGIN||'';
const secret=process.env.SCORE_SECRET||randomBytes(32).toString('hex');
const database=resolve(process.env.SCORE_DB||'.data/christmas.sqlite');
await mkdir(dirname(database),{recursive:true});
const db=new DatabaseSync(database);
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA busy_timeout = 5000;
  CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, score INTEGER NOT NULL, submitted INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS highest_scores ON runs(score DESC, submitted ASC, id ASC);
`);
const best=db.prepare('SELECT name, score FROM runs ORDER BY score DESC, rowid ASC LIMIT 10');
const existing=db.prepare('SELECT score, name FROM runs WHERE id=?');
const save=db.prepare('INSERT OR IGNORE INTO runs(id,name,score,submitted) VALUES(?,?,?,?)');
const mime={'.html':'text/html; charset=utf-8','.mjs':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.webp':'image/webp','.png':'image/png','.ico':'image/x-icon','.webmanifest':'application/manifest+json','.mp3':'audio/mpeg','.wav':'audio/wav'};

function sign(value) {
  return createHmac('sha256',secret).update(value).digest('base64url');
}

function ticket() {
  const id=randomBytes(16).toString('hex');
  const seed=randomBytes(4).readUInt32LE();
  const issued=Date.now();
  const body=`${id}.${seed}.${issued}`;
  return {seed,token:body+'.'+sign(body)};
}

function readTicket(token) {
  if(typeof token!=='string'||!/^[a-f0-9]{32}\.\d{1,10}\.\d{13}\.[A-Za-z0-9_-]{43}$/.test(token)) return null;
  const [id,seed,issued,signature]=token.split('.');
  const expected=sign(`${id}.${seed}.${issued}`);
  const age=Date.now()-Number(issued);
  if(!timingSafeEqual(Buffer.from(signature),Buffer.from(expected))||age<0||age>7_200_000) return null;
  return {id,seed:Number(seed),age};
}

async function readBody(req) {
  let size=0;
  const parts=[];
  for await(const chunk of req) {
    size+=chunk.length;
    if(size>65536) return null;
    parts.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(parts)); } catch { return null; }
}

function send(res,status,body) {
  res.writeHead(status,{
    'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',
    'X-Content-Type-Options':'nosniff'
  });
  res.end(JSON.stringify(body));
}

async function api(req,res,path) {
  const from=req.headers.origin;
  const own=`http://${req.headers.host}`;
  if(from && from!==own && from!==own.replace('http:','https:') && from!==origin) {
    return send(res,403,{error:'Origin not allowed'});
  }
  if(from) {
    res.setHeader('Access-Control-Allow-Origin',from);
    res.setHeader('Vary','Origin');
  }
  if(req.method==='OPTIONS') {
    res.writeHead(204,{'Access-Control-Allow-Methods':'GET, POST, OPTIONS','Access-Control-Allow-Headers':'Content-Type'});
    return res.end();
  }
  if(req.method==='GET' && path==='scores') return send(res,200,{entries:best.all()});
  if(req.method==='POST' && path==='run') {
    req.resume();
    return send(res,200,ticket());
  }
  if(req.method!=='POST'||path!=='scores') return send(res,404,{error:'Not found'});
  if(!req.headers['content-type']?.startsWith('application/json')) return send(res,415,{error:'Expected JSON'});
  const body=await readBody(req);
  const runTicket=readTicket(body?.token);
  const name=typeof body?.name==='string'?body.name.trim().normalize('NFKC'):'';
  if(!runTicket||!name||name.length>24||/[\p{Cc}\p{Cf}]/u.test(name)) {
    return send(res,400,{error:'Invalid run or nickname'});
  }
  const saved=existing.get(runTicket.id);
  if(saved) return send(res,200,{score:saved.score});
  if(!Number.isInteger(body.endTick)||body.endTick*1000/RATE>runTicket.age+1000) {
    return send(res,400,{error:'Invalid finish time'});
  }
  const result=replay(runTicket.seed,body.inputs,body.endTick);
  if(!result||!result.bottles) return send(res,400,{error:'Invalid run'});
  save.run(runTicket.id,name,score(result),Date.now());
  return send(res,201,{score:score(result)});
}

async function staticFile(req,res,path) {
  if(path==='/kombucha') {
    res.writeHead(308,{Location:'/kombucha/'});
    return res.end();
  }
  if(!['GET','HEAD'].includes(req.method)) return send(res,405,{error:'Method not allowed'});
  const publicPath=path.replace(/^\/kombucha(?=\/|$)/,'')||'/';
  const name=publicPath==='/'?'index.html':publicPath.slice(1);
  const permitted=/^(index\.html|kombucha-atlas\.png|(?:christmas|backgrounds|terrain|effects|obstacles|ui|assets|audio)\/[a-zA-Z0-9_.-]+)$/;
  const target=resolve(root,name);
  const type=mime[extname(target)];
  if(!permitted.test(name)||!type||!target.startsWith(root.endsWith(sep)?root:root+sep)) {
    return send(res,404,{error:'Not found'});
  }
  const file=await stat(target).catch(()=>null);
  if(!file?.isFile()) return send(res,404,{error:'Not found'});
  res.writeHead(200,{'Content-Type':type,'Content-Length':file.size,'X-Content-Type-Options':'nosniff'});
  if(req.method==='HEAD') return res.end();
  createReadStream(target).on('error',()=>res.destroy()).pipe(res);
}

createServer(async(req,res)=>{
  try {
    const path=new URL(req.url,'http://localhost').pathname;
    if(path.startsWith(base)) await api(req,res,path.slice(base.length));
    else await staticFile(req,res,path);
  } catch(error) {
    console.error(error);
    if(!res.headersSent) send(res,500,{error:'Server error'});
    else res.end();
  }
}).listen(port,local,()=>console.log(`Kombucha Christmas Run · http://${local}:${port}/kombucha/`));
