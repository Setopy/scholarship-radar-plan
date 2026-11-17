"use strict";
// Scholarship Radar plan lookup. Everything runs in the browser:
// phone/email + a name -> PBKDF2 -> (lookup id, AES key) -> fetch one shard -> decrypt.
const COUNTRIES = ["South Korea", "Malaysia", "Thailand"];
const STEPS = [
  ["Now – Jan 2027", "Email your supervisors. Request transcripts, an English-medium-instruction letter, and start document authentication."],
  ["Jan – Feb 2027", "PTDF (Nigerians, oil & gas fields), IsDB, Monash GEMS. VISTEC Thailand closes 15 Feb 2027."],
  ["Feb – Mar 2027", "Global Korea Scholarship (GKS) embassy deadline; TICA Thailand nomination; SIIT EFS."],
  ["Feb – Apr 2027", "Fall 2027 rounds: KAIST, POSTECH, GIST, UNIST, SNU."],
  ["Mar – Apr 2027", "Malaysia International Scholarship (MIS) call."],
  ["Mar – May 2027", "Mahidol, Chulalongkorn, PSU, KMUTT, KMITL; UTM ASCEND."],
];
const DOCS = ["Passport (valid 18+ months)", "Degree certificate and full transcript", "Grading-scale letter (5-point CGPA)",
  "English-medium-instruction letter or IELTS/TOEFL", "CV (1–2 pages)", "Statement of purpose / research proposal",
  "2–3 recommendation letters", "Authenticated documents (Education / Foreign Affairs)", "NYSC certificate, O'Level results (PTDF)",
  "Publications, if any"];

let PUB = null;
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const safeUrl = (u) => (/^https?:\/\//i.test(u || "") ? esc(u) : "");

function normIdent(v) {
  v = v.trim().toLowerCase();
  if (v.includes("@")) return v;
  const d = v.replace(/\D/g, "");
  return d.length >= 9 ? d.slice(-10) : "";
}
function normName(v) {
  return v.toLowerCase().replace(/[’']/g, "").replace(/[^a-z]/g, "");
}

async function derive(secret) {
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey("raw", enc.encode(secret), "PBKDF2", false, ["deriveBits"]);
  const bits = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: enc.encode(PUB.salt), iterations: PUB.iter }, base, 384));
  const lookup = [...bits.slice(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join("");
  const key = await crypto.subtle.importKey("raw", bits.slice(16), "AES-GCM", false, ["decrypt"]);
  return { lookup, key };
}

async function openPlan(ident, name) {
  const { lookup, key } = await derive(`${ident}|${name}`);
  const shard = await (await fetch(`data/${lookup.slice(0, 2)}.json`, { cache: "no-store" })).json();
  const blob = shard[lookup];
  if (!blob) return null;
  const raw = Uint8Array.from(atob(blob), (c) => c.charCodeAt(0));
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: raw.slice(0, 12) }, key, raw.slice(12));
  return JSON.parse(new TextDecoder().decode(plain));
}

function render(p) {
  const S = PUB.scholarships, P = PUB.supervisors;
  const count = (k) => (p.s[k] || []).length;
  let h = `<div class="card">
    <h2>${esc(p.name)}</h2>
    <dl class="profile">
      <dt>Plan ID</dt><dd>${esc(p.id)}</dd>
      <dt>Course</dt><dd>${esc(p.course)}</dd>
      <dt>Field</dt><dd>${esc(p.field)}</dd>
      <dt>Degree class</dt><dd>${esc(p.class)}</dd>
      <dt>Aiming for</dt><dd>${esc(p.target)}</dd>
    </dl>
    <div class="glance">${COUNTRIES.map((k) => `<div><b>${count(k)}</b>funded option${count(k) === 1 ? "" : "s"}<br><small>${k}</small></div>`).join("")}</div>
    ${p.notes && p.notes.length ? `<p class="note">${esc(p.notes.join(" "))}</p>` : ""}
    <div class="tools"><button class="ghost" onclick="window.print()">Save as PDF / print</button>
    <button class="ghost" onclick="location.reload()">Close</button></div>
  </div>`;

  h += `<div class="card"><h2>Scholarships you can target</h2>
    <p class="muted">Ordered by priority. "Minimum class" is guidance converted to Nigerian degree classes; the official rules always win.</p>`;
  for (const k of COUNTRIES) {
    h += `<h3>${k} (${count(k)})</h3>`;
    if (!count(k)) { h += `<p class="muted">No fully funded scheme here matches your current profile.</p>`; continue; }
    for (const id of p.s[k]) {
      const s = S[id]; if (!s) continue;
      const u = safeUrl(s.url);
      h += `<div class="sch"><div class="t">${esc(s.name)}</div>
        ${s.note ? `<div class="note">${esc(s.note)}</div>` : ""}
        <div class="meta"><b>Covers:</b> ${esc(s.covers)}</div>
        <div class="meta"><b>Minimum class:</b> ${esc(s.min)} · <b>When:</b> ${esc(s.when)}</div>
        ${u ? `<div><a href="${u}" target="_blank" rel="noopener">Official page / apply →</a></div>` : ""}</div>`;
    }
  }
  h += `</div><div class="card"><h2>Your suggested supervisors</h2>
    <p class="muted">One per country, matched to your field. Read 2–3 of their recent papers first, then email each one individually.</p>`;
  for (const k of COUNTRIES) {
    const s = P[(p.p || {})[k]];
    if (!s) { h += `<div class="sup"><div class="c">${k}</div>None found yet for your field.</div>`; continue; }
    const prof = safeUrl(s.profile);
    h += `<div class="sup"><div class="c">${k}</div><div class="n">${esc(s.name)}</div>
      <div>${esc(s.university)}${s.department ? ", " + esc(s.department) : ""}</div>
      <div class="meta"><b>Research:</b> ${esc(s.research)}</div>
      <div>${s.email ? `<a href="mailto:${esc(s.email)}">${esc(s.email)}</a>` : "<i>Email not published: use the profile page</i>"}
      ${prof ? ` · <a href="${prof}" target="_blank" rel="noopener">Profile</a>` : ""}</div>
      ${s.funding ? `<div class="meta"><b>Funding route:</b> ${esc(s.funding)}</div>` : ""}</div>`;
  }
  h += `</div><div class="card"><h2>Your 2027 timeline</h2><table>${STEPS.map(([a, b]) => `<tr><td>${a}</td><td>${b}</td></tr>`).join("")}</table>
    <h3>Document checklist</h3><ul class="checklist">${DOCS.map((d) => `<li>${d}</li>`).join("")}</ul></div>`;
  const el = $("plan");
  el.innerHTML = h;
  el.hidden = false;
  $("login").hidden = true;
  window.scrollTo(0, 0);
}

$("form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const ident = normIdent($("phone").value), name = normName($("first").value);
  const msg = $("msg"), btn = $("go");
  if (!ident) { msg.textContent = "Please enter the phone number (or email) you gave on the form."; return; }
  if (name.length < 2) { msg.textContent = "Please enter your first name."; return; }
  btn.disabled = true; msg.style.color = ""; msg.textContent = "Checking…";
  try {
    PUB = PUB || await (await fetch("public.json")).json();
    const plan = await openPlan(ident, name);
    if (plan) { msg.textContent = ""; render(plan); }
    else msg.textContent = "We couldn't find a plan for those details. Check the phone number and try another of your names, spelt as on the form.";
  } catch (err) {
    msg.textContent = "Something went wrong loading your plan. Please check your connection and try again.";
  } finally { btn.disabled = false; }
});
