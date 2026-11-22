"use strict";
/* CLXBank v3: secure system with Supabase (PostgreSQL) storage and Web Crypto in the browser.
   Salt + pepper hashing, TOTP 2FA, 4 roles with different interfaces, AES-GCM + HMAC,
   audit trail, user-deletion trail, encrypted backups, configuration-only restore. */

const PEPPER = "9f3a6c1e5b7d482a90e4c2f817d3b65a4e0f9c28d1b7a3564c8e2f01a9d7b3e5"; // secret kept in code, apart from the stored data
const ITER = 210000;
const DEF = { maxFails: 5, lockMin: 5, sessionMin: 15, minPw: 10, backupSec: 30, selfReg: 1 };
const PERMS = {
  user:    ["view_own_balance"],
  auditor: ["view_own_balance", "view_state", "view_audit"],
  manager: ["view_own_balance", "view_state", "view_all_balances"],
  admin:   ["view_own_balance", "view_state", "view_all_balances", "view_audit", "view_db", "view_report", "manage_users", "manage_backups"],
};
const TABS = [["home","My account","view_own_balance"],["state","System state","view_state"],["bals","Balances","view_all_balances"],
  ["users","Users","manage_users"],["log","Change log","view_audit"],["db","Database","view_db"],
  ["bk","Backup & config","manage_backups"],["rep","Report","view_report"],["lab","Salt & pepper lab","view_report"]];

const S = crypto.subtle, enc = new TextEncoder(), dec = new TextDecoder(), $ = id => document.getElementById(id);
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
const rnd = n => crypto.getRandomValues(new Uint8Array(n));
const eq = (a, b) => { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; };
const esc = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const say = (t, bad) => { const m = $("msg"); m.textContent = t; m.className = bad ? "bad" : ""; };
const fmt = ts => new Date(ts).toLocaleString();
const safe = fn => async (...a) => { try { await fn(...a); } catch (e) { console.error(e); say("Error: " + e.message, 1); } };
const tbl = (h, rows) => `<div class="sc"><table><tr>${h.map(x => `<th>${x}</th>`).join("")}</tr>${rows.map(r => `<tr>${r.map(c => `<td>${c}</td>`).join("")}</tr>`).join("")}</table></div>`;
const dl = (name, text, type) => { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([text], { type })); a.download = name; a.click(); URL.revokeObjectURL(a.href); };

let db, KEYS, session = null, pending = null, screen = "login", view = "home", repl = null, keys = [], flt = "", bt;
let BK = [], lastUsers = new Set(), auditSynced = 0, syncQ = Promise.resolve(), sb;
const getB = () => BK;
const dbErr = (what, error) => { if (error) { console.error(what, error); say("Database error (" + what + "): " + error.message, 1); } return error; };

/* ---------- Storage: Supabase (PostgreSQL) ---------- */
async function loadAll() {
  let { data: c, error } = await sb.from("config").select("*").eq("id", 1).maybeSingle();
  if (error) { dbErr("config", error); throw new Error("Cannot read the Supabase database. Did you run schema.sql?"); }
  if (!c) { c = { id: 1, salt: b64(rnd(16)), cfg: { ...DEF } }; dbErr("config", (await sb.from("config").insert(c)).error); }
  const [u, d, a, b] = await Promise.all([sb.from("users").select("*"), sb.from("deleted_users").select("*"),
    sb.from("audit_log").select("*").order("id"), sb.from("backups").select("*").order("id")]);
  for (const r of [u, d, a, b]) if (r.error) { dbErr("load", r.error); throw new Error("Cannot read the Supabase database"); }
  db = { salt: c.salt, cfg: { ...DEF, ...c.cfg }, users: {}, deleted: [], audit: [] };
  u.data.forEach(r => db.users[r.username] = { salt: r.salt, hash: r.hash, role: r.role, rec: r.rec, fails: r.fails, lock: r.lock_until, created: r.created, by: r.created_by });
  db.deleted = d.data.map(r => ({ name: r.name, role: r.role, ts: r.ts, by: r.deleted_by, created: r.created, replacedBy: r.replaced_by }));
  db.audit = a.data.map(r => ({ ts: r.ts, user: r.actor, event: r.event, detail: r.detail || "", mac: r.mac }));
  BK = b.data; lastUsers = new Set(Object.keys(db.users)); auditSynced = db.audit.length;
}
const refresh = async () => { await syncQ; await loadAll(); };
function save() {
  syncQ = syncQ.then(sync).catch(e => say("Database error: " + e.message, 1));
  clearTimeout(bt); bt = setTimeout(() => backup("auto"), 2000);
}
async function sync() {
  const rows = Object.entries(db.users).map(([n, r]) => ({ username: n, salt: r.salt, hash: r.hash, role: r.role, rec: r.rec, fails: r.fails, lock_until: r.lock, created: r.created, created_by: r.by }));
  if (rows.length) dbErr("users", (await sb.from("users").upsert(rows)).error);
  const gone = [...lastUsers].filter(n => !db.users[n]);
  if (gone.length) dbErr("users", (await sb.from("users").delete().in("username", gone)).error);
  lastUsers = new Set(Object.keys(db.users));
  if (db.deleted.length) dbErr("deleted_users", (await sb.from("deleted_users").upsert(db.deleted.map(d =>
    ({ name: d.name, role: d.role, ts: d.ts, deleted_by: d.by, created: d.created, replaced_by: d.replacedBy || null })))).error);
  dbErr("config", (await sb.from("config").upsert({ id: 1, salt: db.salt, cfg: db.cfg })).error);
  const fresh = db.audit.slice(auditSynced);
  if (fresh.length) {
    const { error } = await sb.from("audit_log").insert(fresh.map(e => ({ ts: e.ts, actor: e.user, event: e.event, detail: e.detail, mac: e.mac })));
    if (!dbErr("audit_log", error)) auditSynced = db.audit.length;
  }
}

/* ---------- Cryptography ---------- */
async function hmac(keyBytes, data) {
  const k = await S.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await S.sign("HMAC", k, data));
}
// CONCATENATED hashing: password | salt | pepper are joined into one string, then hashed with PBKDF2-SHA256
const concat = (pw, saltHex) => `${pw}|${saltHex}|${PEPPER}`;
const kdf = async (text, salt) => {
  const k = await S.importKey("raw", enc.encode(text), "PBKDF2", false, ["deriveBits"]);
  return hex(await S.deriveBits({ name: "PBKDF2", salt, iterations: ITER, hash: "SHA-256" }, k, 256));
};
const hashPw = (pw, salt) => kdf(concat(pw, hex(salt)), salt);

async function makeKeys(saltB64) {
  const base = await S.importKey("raw", enc.encode(PEPPER), "PBKDF2", false, ["deriveBits"]);
  const master = await S.deriveBits({ name: "PBKDF2", salt: unb64(saltB64), iterations: 100000, hash: "SHA-256" }, base, 256);
  const hk = await S.importKey("raw", master, "HKDF", false, ["deriveKey"]);
  const derive = (info, alg, use) => S.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: enc.encode(info) }, hk, alg, false, use);
  return { aes: await derive("enc", { name: "AES-GCM", length: 256 }, ["encrypt", "decrypt"]),
           mac: await derive("mac", { name: "HMAC", hash: "SHA-256" }, ["sign", "verify"]) };
}
async function seal(obj, keys = KEYS, aad) {
  const iv = rnd(12), p = { name: "AES-GCM", iv };
  if (aad) p.additionalData = enc.encode(aad);
  return { iv: b64(iv), ct: b64(await S.encrypt(p, keys.aes, enc.encode(JSON.stringify(obj)))) };
}
async function open(box, keys = KEYS, aad) {
  const p = { name: "AES-GCM", iv: unb64(box.iv) };
  if (aad) p.additionalData = enc.encode(aad);
  return JSON.parse(dec.decode(await S.decrypt(p, keys.aes, unb64(box.ct))));
}

/* ---------- TOTP 2FA ---------- */
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function b32enc(bytes) { let bits = "", out = ""; for (const b of bytes) bits += b.toString(2).padStart(8, "0");
  for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, "0"), 2)]; return out; }
function b32dec(s) { let bits = "", out = []; for (const c of s) bits += B32.indexOf(c).toString(2).padStart(5, "0");
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2)); return new Uint8Array(out); }
async function totp(secret, counter) {
  const k = await S.importKey("raw", b32dec(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const msg = new DataView(new ArrayBuffer(8)); msg.setUint32(4, counter);
  const h = new Uint8Array(await S.sign("HMAC", k, msg.buffer)), o = h[19] & 15;
  return String((((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 1e6).padStart(6, "0");
}
async function checkTotp(secret, code) {
  const t = Math.floor(Date.now() / 30000);
  for (const d of [-1, 0, 1]) if (await totp(secret, t + d) === code) return true;
  return false;
}

/* ---------- Change log (hash-chained, tamper-evident) ---------- */
async function log(user, event, detail = "") {
  const prev = db.audit.length ? db.audit.at(-1).mac : "";
  const e = { ts: Date.now(), user, event, detail };
  e.mac = b64(await S.sign("HMAC", KEYS.mac, enc.encode(prev + JSON.stringify(e))));
  db.audit.push(e); save();
}
async function chain() {
  let prev = "";
  for (let i = 0; i < db.audit.length; i++) {
    const { ts, user, event, detail, mac } = db.audit[i];
    if (!await S.verify("HMAC", KEYS.mac, unb64(mac), enc.encode(prev + JSON.stringify({ ts, user, event, detail })))) return i + 1;
    prev = mac;
  }
  return 0;
}
const fp = async () => hex(await S.digest("SHA-256", enc.encode(JSON.stringify([db.users, db.deleted])))); // fingerprint of the DATA

/* ---------- Backups: full encrypted snapshot; restore applies CONFIGURATION ONLY ---------- */
async function backup(kind) {
  if (!Object.keys(db.users).length) return null;
  const box = await seal(db);
  const mac = b64(await S.sign("HMAC", KEYS.mac, enc.encode(db.salt + box.iv + box.ct)));
  const env = { v: 2, ts: Date.now(), kind, salt: db.salt, ...box, mac };
  const { data, error } = await sb.from("backups").insert({ ts: env.ts, kind, salt: env.salt, iv: env.iv, ct: env.ct, mac: env.mac }).select().single();
  if (dbErr("backups", error)) return env;
  BK.push(data); while (BK.length > 5) { const o = BK.shift(); await sb.from("backups").delete().eq("id", o.id); }
  return env;
}
async function restoreCfg(env, by) {
  const k = await makeKeys(env.salt);
  if (!await S.verify("HMAC", k.mac, unb64(env.mac), enc.encode(env.salt + env.iv + env.ct)))
    throw new Error("INTEGRITY CHECK FAILED: backup was modified. Nothing restored.");
  const snap = await open(env, k), before = await fp();
  const changes = Object.keys(DEF).filter(x => db.cfg[x] !== snap.cfg[x]).map(x => `${x}: ${db.cfg[x]} -> ${snap.cfg[x]}`);
  db.cfg = { ...DEF, ...snap.cfg };                                   // only the configuration is replaced
  await log(by, "CONFIG_RESTORED", (changes.join("; ") || "no differences") + " | users, balances and trail untouched");
  return { before, after: await fp(), changes };
}
const restMsg = r => r.before === r.after
  ? say(`Configuration restored (${r.changes.length} setting(s) changed). Data fingerprint unchanged: ${r.before.slice(0, 12)}… OK`)
  : say("WARNING: data fingerprint changed", 1);

/* ---------- Rules ---------- */
const strong = p => p.length >= db.cfg.minPw && /[a-z]/.test(p) && /[A-Z]/.test(p) && /\d/.test(p) && /[^\w\s]/.test(p);
async function need(p) {
  if (!session || Date.now() > session.exp) { session = null; screen = "login"; render(); say("Login required", 1); return false; }
  if (!PERMS[session.role].includes(p)) { await log(session.user, "DENIED", p); say("Forbidden: your role lacks this permission", 1); return false; }
  session.exp = Date.now() + db.cfg.sessionMin * 60000; return true;
}
async function addUser(name, pw, role, by) {
  if (!/^[A-Za-z0-9_]{3,30}$/.test(name)) throw new Error("Username: 3 to 30 letters, numbers or _");
  if (!strong(pw)) throw new Error(`Password needs ${db.cfg.minPw}+ characters with upper case, lower case, a number and a symbol`);
  if (!PERMS[role]) throw new Error("Unknown role");
  if (db.users[name] || db.deleted.some(d => d.name === name)) throw new Error("Username unavailable (names of deleted users are never reused)");
  const salt = rnd(16), secret = b32enc(rnd(20));
  db.users[name] = { salt: b64(salt), hash: await hashPw(pw, salt), role, rec: await seal({ balance: 1000, totp: secret }, KEYS, name),
                     fails: 0, lock: 0, created: Date.now(), by };
  await log(by, "USER_CREATED", `${name} as ${role}`);
  return secret;
}

/* ---------- Views (each role sees only the tabs its permissions allow) ---------- */
const views = {};
const keyBox = () => keys.length ? `<div class="card warn-box"><b>One-time 2FA setup keys.</b> Add each key to an authenticator app (Enter a setup key, time-based), then dismiss.`
  + tbl(["User", "Setup key", "Demo password"], keys.map(k => [esc(k.name), `<code>${esc(k.secret)}</code>`, esc(k.pw || "as typed")]))
  + `<button data-a="dk" class="grey">Dismiss</button></div>` : "";
const labHtml = () => `<h2>Salt &amp; pepper lab</h2><div class="card"><input id="lp2" value="Clave#Segura123" placeholder="Type any password"><button data-a="lab">Show hashing steps</button></div><div id="labout"></div>`;

views.home = async () => {
  const r = db.users[session.user]; let bal;
  try { bal = (await open(r.rec, KEYS, session.user)).balance; } catch (e) { bal = "INTEGRITY ERROR"; }
  const mine = db.audit.filter(e => e.user === session.user).slice(-6).reverse();
  return `<h2>Welcome, ${esc(session.user)} <span class="tag">${session.role}</span></h2><div class="card"><p class="big">Balance: ${esc(bal)}</p>
    <input id="amt" type="number" min="1" placeholder="Amount"><div class="row"><button data-a="dep">Deposit</button><button data-a="wd" class="grey">Withdraw</button></div></div>
    <h3>My recent activity</h3>` + tbl(["Time", "Event", "Detail"], mine.map(e => [fmt(e.ts), esc(e.event), esc(e.detail)]));
};
views.state = async () => {
  const u = Object.values(db.users), by = {}; u.forEach(x => by[x.role] = (by[x.role] || 0) + 1);
  const b = getB(), bad = await chain(), f = await fp();
  const cards = [["Users", u.length], ["Roles", Object.entries(by).map(([k, v]) => k + ": " + v).join(", ")],
    ["Locked accounts", u.filter(x => x.lock > Date.now()).length], ["Deleted users (trail)", db.deleted.length], ["Backups kept", b.length],
    ["Last backup", b.length ? fmt(b.at(-1).ts) : "none"], ["Change log entries", db.audit.length],
    ["Log integrity", bad ? "BROKEN at entry " + bad : "intact"], ["Data fingerprint", f.slice(0, 16) + "…"], ["Session expires", fmt(session.exp)]];
  return `<h2>Current system state</h2><div class="grid">${cards.map(([k, v]) => `<div class="card"><small>${k}</small><b>${esc(v)}</b></div>`).join("")}</div>
    <h3>Configuration</h3>` + tbl(["Setting", "Value"], Object.entries(db.cfg).map(([k, v]) => [k, v]));
};
views.bals = async () => {
  const rows = [];
  for (const [n, r] of Object.entries(db.users)) { let b; try { b = (await open(r.rec, KEYS, n)).balance; } catch (e) { b = "INTEGRITY ERROR"; } rows.push([esc(n), r.role, esc(b)]); }
  return `<h2>All balances</h2>` + tbl(["User", "Role", "Balance"], rows);
};
views.users = async () => {
  const rp = repl ? `<div class="card warn-box">User <b>${esc(repl.name)}</b> (${repl.role}) was deleted and archived in the trail. Create a replacement account below.</div>` : "";
  const rows = Object.entries(db.users).map(([n, r]) => { const lk = r.lock > Date.now(); return [esc(n),
    `<select data-c="role" data-u="${esc(n)}">${Object.keys(PERMS).map(x => `<option${x === r.role ? " selected" : ""}>${x}</option>`).join("")}</select>`,
    lk ? "LOCKED" : "active", (lk ? `<button data-a="unlock" data-u="${esc(n)}">Unlock</button> ` : "") + `<button data-a="del" data-u="${esc(n)}" class="warn">Delete</button>`]; });
  return `<h2>User management</h2>${keyBox()}${rp}<div class="card"><h3>Add user</h3><input id="nu" placeholder="Username"><input id="np" type="password" placeholder="Password">
    <select id="nr">${Object.keys(PERMS).map(x => `<option${repl && repl.role === x ? " selected" : ""}>${x}</option>`).join("")}</select>
    <div class="row"><button data-a="add">Create user</button><button data-a="demo" class="grey">Add demo users</button></div></div>`
    + tbl(["User", "Role", "Status", "Actions"], rows) + `<h3>Deleted users (trail)</h3>`
    + tbl(["User", "Role", "Deleted", "By", "Replaced by"], db.deleted.map(d => [esc(d.name), d.role, fmt(d.ts), esc(d.by), esc(d.replacedBy || "-")]));
};
views.log = async () => {
  const rows = db.audit.filter(e => !flt || (e.user + e.event + e.detail).toLowerCase().includes(flt)).slice(-200).reverse()
    .map(e => [fmt(e.ts), esc(e.user), esc(e.event), esc(e.detail)]);
  return `<h2>Change log</h2><div class="row"><input id="flt" placeholder="Filter (user, event, detail)" value="${esc(flt)}"><button data-a="filter">Filter</button><button data-a="chain" class="grey">Verify chain</button></div>`
    + tbl(["Time", "By", "Event", "Detail"], rows);
};
views.db = async () => `<h2>System database (read-only view)</h2><h3>users</h3>`
  + tbl(["username", "role", "salt (hex)", "password hash", "encrypted record (iv / ciphertext)", "failed", "created", "by"],
    Object.entries(db.users).map(([n, r]) => [esc(n), r.role, `<code>${hex(unb64(r.salt))}</code>`, `<code>${r.hash.slice(0, 24)}…</code>`,
      `<code>${esc(r.rec.iv)} / ${esc(r.rec.ct.slice(0, 20))}…</code>`, r.fails, fmt(r.created), esc(r.by)]))
  + `<h3>deleted_users</h3>` + tbl(["name", "role", "deleted", "by", "replaced by"], db.deleted.map(d => [esc(d.name), d.role, fmt(d.ts), esc(d.by), esc(d.replacedBy || "-")]))
  + `<h3>config</h3><pre>${esc(JSON.stringify(db.cfg, null, 1))}</pre><h3>backups</h3>`
  + tbl(["time", "kind", "content"], getB().map(b => [fmt(b.ts), b.kind, b.ct.length + " chars, AES-GCM encrypted + HMAC signed"]))
  + `<h3>audit_log: ${db.audit.length} entries (see Change log)</h3>`;
views.bk = async () => `<h2>Backup &amp; configuration</h2><div class="card"><h3>Configuration</h3><div class="grid2">
  ${Object.entries(db.cfg).map(([k, v]) => `<label class="small">${k}<input id="c_${k}" type="number" value="${v}"></label>`).join("")}</div><button data-a="savecfg">Save configuration</button></div>
  <div class="card"><h3>Backups (encrypted and signed, automatic every ${db.cfg.backupSec}s and after changes)</h3>
  <p class="small">A restore applies the saved <b>configuration only</b>. Users, balances and logs are never changed by it.</p>`
  + tbl(["Time", "Kind", ""], getB().map((x, i) => [fmt(x.ts), x.kind, `<button data-a="rest" data-i="${i}">Restore config</button>`]))
  + `<div class="row"><button data-a="bnow">Backup now</button><button data-a="bdl" class="grey">Download</button><button data-a="tamper" class="warn">Tamper test</button></div>
  <label class="small">Restore config from file <input type="file" data-c="bfile" accept=".json"></label></div>`;
views.rep = async () => `<h2>Security report</h2><div class="card"><p><b>Pepper</b> (secret, shown only for this assignment): <code>${PEPPER}</code></p>
  <p class="small">Method: concatenate password | salt | pepper, then PBKDF2-SHA256 with ${ITER} rounds; random 16-byte salt per user. Generated ${fmt(Date.now())}.</p></div>`
  + tbl(["User", "Role", "Salt (hex)", "Password hash (hex)", "Status"], Object.entries(db.users).map(([n, r]) =>
      [esc(n), r.role, `<code>${hex(unb64(r.salt))}</code>`, `<code>${r.hash}</code>`, r.lock > Date.now() ? "locked" : "active"]))
  + `<h3>Deleted users</h3>` + tbl(["User", "Role", "Deleted", "By", "Replaced by"], db.deleted.map(d => [esc(d.name), d.role, fmt(d.ts), esc(d.by), esc(d.replacedBy || "-")]))
  + `<div class="row"><button data-a="csv">Download CSV</button><button data-a="print" class="grey">Print / save as PDF</button></div>`;
views.lab = async () => labHtml();

/* ---------- Screens ---------- */
function render() {
  const app = $("app"), first = !Object.keys(db.users).length;
  $("out").hidden = screen !== "app"; $("who").textContent = session && screen === "app" ? `${session.user} · ${session.role}` : "";
  if (screen === "app") {
    $("tabs").innerHTML = TABS.filter(t => PERMS[session.role].includes(t[2])).map(t => `<a data-a="tab" data-v="${t[0]}" class="${t[0] === view ? "on" : ""}">${t[1]}</a>`).join("");
    views[view]().then(h => app.innerHTML = h).catch(e => say("Error: " + e.message, 1)); return;
  }
  $("tabs").innerHTML = "";
  app.innerHTML = keyBox() + (screen === "lab" ? labHtml() + `<button data-a="to" data-s="login" class="grey">Back</button>`
    : screen === "reg" ? `<div class="card"><h2>Create account</h2><p class="small">New accounts always get the user role. You will get a 2FA setup key to add to your authenticator app.</p><input id="ru" placeholder="Username (letters, numbers, _)"><input id="rp" type="password" placeholder="Password (10+ chars, upper, lower, number, symbol)"><button data-a="register">Register</button><button data-a="to" data-s="login" class="grey">Back</button></div>`
    : screen === "2fa" ? `<div class="card"><h2>Two-factor code (step 2 of 2)</h2><input id="code" placeholder="6-digit code" inputmode="numeric" maxlength="10" autocomplete="one-time-code"><button data-a="verify">Verify</button></div>`
    : first ? `<div class="card"><h2>First start: create the administrator</h2><input id="lu" placeholder="Username"><input id="lp" type="password" placeholder="Password"><button data-a="first">Create administrator</button></div>`
    : `<div class="card"><h2>Log in (step 1 of 2)</h2><input id="lu" placeholder="Username" autocomplete="username"><input id="lp" type="password" placeholder="Password" autocomplete="current-password"><button data-a="login">Continue</button></div>`)
    + (screen === "login" ? (db.cfg.selfReg && !first ? `<button data-a="to" data-s="reg">Create account</button>` : "") + `<button data-a="to" data-s="lab" class="grey">Salt &amp; pepper lab</button>` : "");
}

/* ---------- Actions ---------- */
const act = {}, chg = {};
document.addEventListener("click", e => { const b = e.target.closest("[data-a]"); if (b && act[b.dataset.a]) safe(act[b.dataset.a])(b.dataset); });
document.addEventListener("change", e => { const el = e.target.closest("[data-c]"); if (el && chg[el.dataset.c]) safe(chg[el.dataset.c])(el); });
$("out").onclick = safe(async () => { if (session) await log(session.user, "LOGOUT"); session = null; screen = "login"; render(); say("Logged out"); });

act.to = d => { screen = d.s; render(); };
act.dk = () => { keys = []; render(); };
act.first = async () => {
  if (Object.keys(db.users).length) return;
  const n = $("lu").value.trim(), s = await addUser(n, $("lp").value, "admin", "system");
  keys = [{ name: n, secret: s }]; render(); say("Administrator created. Add the setup key to your authenticator app, then log in.");
};
act.register = async () => {
  await refresh();
  if (!db.cfg.selfReg) throw new Error("Self-registration is closed. Ask an administrator for an account.");
  if (!Object.keys(db.users).length) throw new Error("The system has no administrator yet");
  const n = $("ru").value.trim(), s = await addUser(n, $("rp").value, "user", n);
  keys = [{ name: n, secret: s }]; screen = "login"; render();
  say("Account created with the user role. Add the setup key to your authenticator app, then log in.");
};
act.login = async () => {
  await refresh();
  const u = $("lu").value.trim(), p = $("lp").value, r = db.users[u];
  if (r && r.lock > Date.now()) return say("Account temporarily locked", 1);
  const h = await hashPw(p, r ? unb64(r.salt) : rnd(16));
  if (!(r && eq(h, r.hash))) {
    if (r) { r.fails++; if (r.fails >= db.cfg.maxFails) { r.lock = Date.now() + db.cfg.lockMin * 60000; r.fails = 0; await log(u, "ACCOUNT_LOCKED", `after ${db.cfg.maxFails} failed logins`); } save(); }
    await log(u, "LOGIN_FAIL"); return say("Invalid credentials", 1);
  }
  r.fails = 0; save(); pending = { u, at: Date.now() }; screen = "2fa"; render(); say("Password OK. Enter your authenticator code.");
};
act.verify = async () => {
  if (!pending || Date.now() - pending.at > 120000) { pending = null; screen = "login"; render(); return say("Start again", 1); }
  const r = db.users[pending.u]; let rec;
  try { rec = await open(r.rec, KEYS, pending.u); } catch (e) { return say("INTEGRITY FAILURE: this user record was tampered with", 1); }
  if (!await checkTotp(rec.totp, $("code").value.replace(/\D/g, ""))) { await log(pending.u, "2FA_FAIL"); return say("Invalid code. Check that your phone and computer clocks match.", 1); }
  session = { user: pending.u, role: r.role, exp: Date.now() + db.cfg.sessionMin * 60000 };
  pending = null; screen = "app"; view = "home"; await log(session.user, "LOGIN_OK"); render(); say("Logged in");
};
act.tab = async d => { const t = TABS.find(x => x[0] === d.v); if (!await need(t[2])) return; view = d.v; await refresh(); render(); };
const money = async sign => {
  if (!await need("view_own_balance")) return;
  const a = Number($("amt").value); if (!(a > 0)) throw new Error("Enter a positive amount");
  const r = db.users[session.user], rec = await open(r.rec, KEYS, session.user);
  if (sign < 0 && a > rec.balance) throw new Error("Insufficient funds");
  const old = rec.balance; rec.balance += sign * a; r.rec = await seal(rec, KEYS, session.user);
  await log(session.user, sign > 0 ? "DEPOSIT" : "WITHDRAW", `${a}: balance ${old} -> ${rec.balance}`); render();
};
act.dep = () => money(1); act.wd = () => money(-1);
act.add = async () => {
  if (!await need("manage_users")) return;
  const n = $("nu").value.trim(), s = await addUser(n, $("np").value, $("nr").value, session.user);
  if (repl) { const d = db.deleted.find(x => x.name === repl.name); if (d) { d.replacedBy = n; await log(session.user, "REPLACEMENT", `${n} replaces deleted user ${repl.name}`); } repl = null; }
  keys.unshift({ name: n, secret: s }); render(); say("User created. Add the setup key to an authenticator app.");
};
act.demo = async () => {
  if (!await need("manage_users")) return;
  for (const [n, p, r] of [["manager1", "Manager#Demo2026", "manager"], ["auditor1", "Auditor#Demo2026", "auditor"], ["user1", "User#Demo2026", "user"]])
    if (!db.users[n] && !db.deleted.some(d => d.name === n)) keys.unshift({ name: n, pw: p, secret: await addUser(n, p, r, session.user) });
  render(); say("Demo users added: manager1, auditor1, user1");
};
act.unlock = async d => { if (!await need("manage_users")) return; const r = db.users[d.u]; r.lock = 0; r.fails = 0; await log(session.user, "USER_UNLOCKED", d.u); render(); };
act.del = async d => {
  if (!await need("manage_users")) return;
  const n = d.u, r = db.users[n];
  if (n === session.user) throw new Error("You cannot delete your own account");
  if (r.role === "admin" && Object.values(db.users).filter(x => x.role === "admin").length < 2) throw new Error("Cannot delete the last administrator");
  if (!confirm(`Delete ${n}? The account is archived in the trail.`)) return;
  db.deleted.push({ name: n, role: r.role, ts: Date.now(), by: session.user, created: r.created }); delete db.users[n];
  await log(session.user, "USER_DELETED", `${n} (${r.role}) archived in the trail`);
  repl = { name: n, role: r.role }; render(); say("User deleted and archived. Create a replacement account below.");
};
chg.role = async el => {
  if (!await need("manage_users")) return;
  const n = el.dataset.u, r = db.users[n], nr = el.value, old = r.role;
  if (old === "admin" && nr !== "admin" && Object.values(db.users).filter(x => x.role === "admin").length < 2) { render(); throw new Error("Cannot demote the last administrator"); }
  r.role = nr; await log(session.user, "ROLE_CHANGED", `${n}: ${old} -> ${nr}`); render(); say("Role updated");
};
act.filter = () => { flt = $("flt").value.toLowerCase(); render(); };
act.chain = async () => { if (!await need("view_audit")) return; const i = await chain(); say(i ? `INTEGRITY FAILURE: change log modified at entry ${i}` : `Change log verified: ${db.audit.length} entries intact`, !!i); };
act.savecfg = async () => {
  if (!await need("manage_backups")) return;
  const nc = {}, ch = [];
  for (const k of Object.keys(DEF)) {
    const v = Math.floor(Number($("c_" + k).value)); if (k === "selfReg" ? !(v === 0 || v === 1) : !(v >= 1)) throw new Error(k === "selfReg" ? "selfReg must be 1 (open) or 0 (closed)" : `${k} must be a positive number`);
    if (k === "minPw" && v < 8) throw new Error("minPw must be at least 8"); nc[k] = v; if (v !== db.cfg[k]) ch.push(`${k}: ${db.cfg[k]} -> ${v}`);
  }
  db.cfg = nc; await log(session.user, "CONFIG_CHANGED", ch.join("; ") || "no changes"); render(); say(ch.length ? "Configuration saved" : "No changes");
};
act.bnow = async () => { if (!await need("manage_backups")) return; await backup("manual"); await log(session.user, "BACKUP_CREATED", "manual"); render(); say("Encrypted backup created"); };
act.bdl = async () => { if (!await need("manage_backups")) return; const env = await backup("download"); dl("clxbank-backup-" + Date.now() + ".json", JSON.stringify(env), "application/json"); await log(session.user, "BACKUP_DOWNLOADED", ""); render(); };
act.rest = async d => { if (!await need("manage_backups")) return; const r = await restoreCfg(getB()[d.i], session.user); render(); restMsg(r); };
chg.bfile = async el => { if (!await need("manage_backups")) return; const env = JSON.parse(await el.files[0].text()); el.value = ""; const r = await restoreCfg(env, session.user); render(); restMsg(r); };
act.tamper = async () => {
  if (!await need("manage_backups")) return;
  const b = getB(); if (!b.length) return say("Make a backup first", 1);
  const x = b.at(-1); x.ct = x.ct.slice(0, -4) + (x.ct.slice(-4) === "AAAA" ? "BBBB" : "AAAA");
  dbErr("backups", (await sb.from("backups").update({ ct: x.ct }).eq("id", x.id)).error); say("Latest backup corrupted on purpose. Click its 'Restore config' button to see the integrity check fail.");
};
act.csv = async () => {
  if (!await need("view_report")) return;
  const q = v => `"${String(v).replace(/"/g, '""')}"`;
  const L = [["PEPPER", PEPPER], ["METHOD", `concatenation (password|salt|pepper) then PBKDF2-SHA256 ${ITER} rounds`], [], ["username", "role", "salt_hex", "password_hash_hex", "status"],
    ...Object.entries(db.users).map(([n, r]) => [n, r.role, hex(unb64(r.salt)), r.hash, r.lock > Date.now() ? "locked" : "active"]), [],
    ["deleted_user", "role", "deleted_at", "by", "replaced_by"], ...db.deleted.map(d => [d.name, d.role, new Date(d.ts).toISOString(), d.by, d.replacedBy || ""])];
  dl("clxbank-report.csv", L.map(r => r.map(q).join(",")).join("\n"), "text/csv");
};
act.print = () => window.print();
act.lab = async () => {
  const pw = $("lp2").value, sa = rnd(16), sb2 = rnd(16), c = x => `<code>${esc(x)}</code>`;
  const cat = concat(pw, hex(sa)), sha = hex(await S.digest("SHA-256", enc.encode(cat)));
  const [h1, h2, h3] = await Promise.all([kdf(cat, sa), kdf(concat(pw, hex(sb2)), sb2), kdf(pw + "|" + hex(sa), sa)]);
  $("labout").innerHTML = tbl(["Step", "Value"], [["1. Password", esc(pw)], ["2. Random salt A", c(hex(sa))], ["3. Pepper (secret kept in the code)", c(PEPPER)],
    ["4. Concatenation: password | salt | pepper", c(cat)], ["5. Plain SHA-256 of the concatenation (illustration)", c(sha)],
    [`6. PBKDF2 x${ITER} of the concatenation = STORED HASH`, c(h1)], ["7. Same password, salt B (different hash)", c(h2)], ["8. Same salt A, NO pepper (different hash)", c(h3)]])
    + `<p class="small">One password, three different results. The salt makes every user's hash unique, and the pepper, kept apart from the stored data, means a stolen database alone cannot be cracked.</p>`;
};

/* ---------- Start ---------- */
(async () => {
  if (!crypto.subtle) return say("Web Crypto unavailable: open this page over https:// or http://localhost", 1);
  if (!window.SUPABASE_URL || window.SUPABASE_URL.includes("YOUR-PROJECT")) return say("Set your Supabase URL and anon key in config.js first.", 1);
  sb = supabase.createClient(window.SUPABASE_URL, window.SUPABASE_KEY);
  await loadAll(); KEYS = await makeKeys(db.salt); render();
  const tick = () => { backup("auto"); setTimeout(tick, Math.max(5, db.cfg.backupSec) * 1000); };
  setTimeout(tick, db.cfg.backupSec * 1000);
  setInterval(() => { if (session && Date.now() > session.exp) { session = null; screen = "login"; render(); say("Session expired", 1); } }, 5000);
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => {});
})().catch(e => say("Error: " + e.message, 1));
