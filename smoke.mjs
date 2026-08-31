import fs from 'node:fs';
import path from 'node:path';

const BASE = 'http://127.0.0.1:8788/api.php';
const ROOM = 'testroom';
const PASS = 'correct horse battery';
const DIR = path.dirname(new URL(import.meta.url).pathname).replace(/^\/([A-Za-z]:)/, '$1');
const ROOMS_DIR = path.join(DIR, 'rooms');

const _te = new TextEncoder();
const _td = new TextDecoder();
const enc = (s) => _te.encode(s);
const dec = (u8) => _td.decode(u8);
const b64 = (u8) => Buffer.from(u8).toString('base64');
const unb64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));

const fails = [];
const ok = (label, cond) => { console.log((cond ? 'PASS  ' : 'FAIL  ') + label); if (!cond) fails.push(label); };

async function deriveKey(pass, room) {
  const km = await crypto.subtle.importKey('raw', enc(pass), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc('ephchat|' + room), iterations: 200000, hash: 'SHA-256' }, km, 256);
  return crypto.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
async function seal(k, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, bytes));
  const o = new Uint8Array(12 + ct.length);
  o.set(iv, 0); o.set(ct, 12);
  return o;
}
async function unseal(k, p) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: p.subarray(0, 12) }, k, p.subarray(12)));
}
async function api(body) {
  const r = await fetch(BASE, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: r.status, body: await r.json() };
}
const keyA = await deriveKey(PASS, ROOM);
const keyWrong = await deriveKey('wrong password', ROOM);
const CID_A = 'aaaaaa';
const CID_B = 'bbbbbb';

const hello = await api({ a: 'hello', room: ROOM });
ok('hello ok', hello.status === 200 && hello.body.ok === true);
ok('expires in ~30 min', Math.abs(hello.body.expires - Math.floor(Date.now() / 1000) - 1800) < 5);

await api({ a: 'burn', room: ROOM });
const p0 = await api({ a: 'poll', room: ROOM, since: 0 });
ok('poll on missing room returns gone', p0.body.gone === true);

const SECRET = '';
const res = await api({ a: 'post', room: ROOM, payload: b64(await seal(keyA, enc(JSON.stringify({ cid: CID_A, k: 'text', v: SECRET })))) });
ok('post accepted', res.status === 200 && res.body.ok === true);

const files = fs.readdirSync(ROOMS_DIR).filter((f) => f.endsWith('.json'));
ok('room file created', files.length === 1);
const disk = fs.readFileSync(path.join(ROOMS_DIR, files[0]), 'utf8');
ok('no plaintext on disk', !disk.includes(SECRET) && !disk.includes('老地方'));
ok('disk has ciphertext only', /"p":"[A-Za-z0-9+/=]+"/.test(disk));

const got = await api({ a: 'poll', room: ROOM, since: 0 });
const first = got.body.msgs[0];
ok('poll returns the message', got.body.msgs.length === 1 && first.i === 1);
const plain = JSON.parse(dec(await unseal(keyA, unb64(first.p))));
ok('A decrypts own text: ' + plain.v, plain.v === SECRET);

let wrongFail = false;
try { await unseal(keyWrong, unb64(first.p)); } catch { wrongFail = true; }
ok('wrong password cannot decrypt', wrongFail);

const inc = await api({ a: 'poll', room: ROOM, since: 1 });
ok('since skips delivered messages', inc.body.msgs.length === 0);

const meta = enc(JSON.stringify({ name: 'shot.png', type: 'image/png', size: 5 }));
const body = new Uint8Array([137, 80, 78, 71, 13]);
const packed = new Uint8Array(4 + meta.length + body.length);
new DataView(packed.buffer).setUint32(0, meta.length);
packed.set(meta, 4); packed.set(body, 4 + meta.length);
const fb64 = b64(await seal(keyA, packed));
const CH = 512 * 1024;
const total = Math.ceil(fb64.length / CH);
const fid = 'f0001';
await api({ a: 'post', room: ROOM, payload: b64(await seal(keyA, enc(JSON.stringify({ cid: CID_A, k: 'fmeta', id: fid, total })))) });
for (let i = 0; i < total; i++) {
  await api({ a: 'post', room: ROOM, payload: b64(await seal(keyA, enc(JSON.stringify({ cid: CID_A, k: 'fchunk', id: fid, seq: i, data: fb64.slice(i * CH, (i + 1) * CH) })))) });
}
const after = await api({ a: 'poll', room: ROOM, since: 1 });
const parts = [];
let fmeta = null;
for (const m of after.body.msgs) {
  const env = JSON.parse(dec(await unseal(keyA, unb64(m.p))));
  if (env.k === 'fmeta') fmeta = env;
  if (env.k === 'fchunk') parts[env.seq] = env.data;
}
ok('file meta received', fmeta && fmeta.total === total);
ok('all chunks received', parts.length === total && parts.every((p) => p !== undefined));
const fp = await unseal(keyA, unb64(parts.join('')));
const mlen = new DataView(fp.buffer, fp.byteOffset, fp.byteLength).getUint32(0);
const fmetaOut = JSON.parse(dec(fp.subarray(4, 4 + mlen)));
ok('file name decrypted: ' + fmetaOut.name, fmetaOut.name === 'shot.png');
ok('file bytes intact', Buffer.compare(Buffer.from(fp.subarray(4 + mlen)), Buffer.from(body)) === 0);

for (const bad of ['', '../../etc/passwd', 'a'.repeat(64), 'room/with/slash']) {
  const r = await api({ a: 'hello', room: bad });
  ok('rejects room name: ' + JSON.stringify(bad.slice(0, 18)), r.status === 400 && r.body.error === 'bad room');
}

const cnRoom = '';
const cn = await api({ a: 'hello', room: cnRoom });
ok('chinese room name accepted', cn.status === 200 && cn.body.ok === true);
await api({ a: 'burn', room: cnRoom });

const big = await api({ a: 'post', room: ROOM, payload: 'x'.repeat(1048577) });
ok('oversized payload rejected', big.status === 400 && big.body.error === 'bad payload');
const get = await fetch(BASE);
ok('GET rejected with 405', get.status === 405);
const junk = await api({ a: 'nope', room: ROOM });
ok('unknown action rejected', junk.status === 400 && junk.body.error === 'unknown action');

await api({ a: 'burn', room: ROOM });
const gone = await api({ a: 'poll', room: ROOM, since: 0 });
ok('burn deletes room file', gone.body.gone === true);
ok('rooms dir empty after burn', fs.readdirSync(ROOMS_DIR).filter((f) => f.endsWith('.json')).length === 0);

console.log(fails.length ? '\n' + fails.length + ' FAILED' : '\nALL PASS');
process.exit(fails.length ? 1 : 0);
