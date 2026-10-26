const tables={fuel:"fuelio_records",odo:"odo_readings",odoApp:"odo_trips"};
const json=(v,status=200)=>new Response(JSON.stringify(v),{status,headers:{"content-type":"application/json","cache-control":"no-store","x-content-type-options":"nosniff"}});
const enc=new TextEncoder();
const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");
async function sign(secret,value){const key=await crypto.subtle.importKey("raw",enc.encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);return b64(await crypto.subtle.sign("HMAC",key,enc.encode(value)))}
async function authorized(request,secret){const token=request.headers.get("authorization")?.replace(/^Bearer /,"")||"";const [expiry,signature]=token.split(".");if(!expiry||!signature||!/^\d+$/.test(expiry)||Number(expiry)<Date.now())return false;const expected=await sign(secret,expiry);return signature.length===expected.length&&signature.split("").every((c,i)=>c===expected[i])}
export async function onRequest({request,env}){try{
if(!env.DB)return json({error:"D1 database not bound"},503);
if(!env.MYDRIVE_PASSWORD||env.MYDRIVE_PASSWORD.length<16)return json({error:"Cloud login is not configured. Set MYDRIVE_PASSWORD as a secret of at least 16 characters."},503);
const url=new URL(request.url);
if(request.method==="POST"&&url.pathname==="/api/sync/login"){const body=await request.json();if(typeof body.password!=="string"||body.password.length>256)return json({error:"Invalid password"},400);const a=enc.encode(body.password),b=enc.encode(env.MYDRIVE_PASSWORD);let diff=a.length^b.length;for(let i=0;i<Math.max(a.length,b.length);i++)diff|=(a[i]||0)^(b[i]||0);if(diff)return json({error:"Incorrect password"},401);const expiry=String(Date.now()+12*3600*1000);return json({token:expiry+"."+await sign(env.MYDRIVE_PASSWORD,expiry)})}
if(!await authorized(request,env.MYDRIVE_PASSWORD))return json({error:"Please sign in"},401);
if(request.method==="GET"){const result={fuel:[],odo:[],odoApp:[]};for(const [k,t] of Object.entries(tables)){const rows=await env.DB.prepare("SELECT payload FROM "+t).all();result[k]=rows.results.map(r=>JSON.parse(r.payload))}return json({data:result})}
if(request.method==="POST"){const body=await request.json();if(!body||!Object.keys(tables).includes(body.type)||!Array.isArray(body.records)||body.records.length>300)return json({error:"Invalid data batch (maximum 300)"},400);const t=tables[body.type],statements=[];for(const r of body.records){if(!r||typeof r!=="object"||Array.isArray(r)||JSON.stringify(r).length>8192)return json({error:"Invalid record"},400);const raw=JSON.stringify(r);const digest=await crypto.subtle.digest("SHA-256",enc.encode(raw));const id=Array.from(new Uint8Array(digest)).map(x=>x.toString(16).padStart(2,"0")).join("");statements.push(env.DB.prepare("INSERT OR IGNORE INTO "+t+" (id,payload) VALUES (?,?)").bind(id,JSON.stringify(r)))}if(statements.length)await env.DB.batch(statements);return json({saved:statements.length})}
return json({error:"Method not allowed"},405)
}catch(e){return json({error:"Cloud sync failed"},500)}}
