#!/usr/bin/env node
/**
 * OVP-1 — témoin de journal public.
 *
 * Un fichier, aucune dépendance, Node 18+.
 *
 * Ce que fait ce script, à chaque exécution :
 *   1. récupère la tête d'arbre signée du journal ;
 *   2. vérifie la signature du journal, avec sa clé ÉPINGLÉE à la première exécution ;
 *   3. exige une preuve de consistance depuis la dernière tête que TU as vue ;
 *   4. ne cosigne QUE si cette preuve est valide.
 *
 * Un témoin qui signe sans vérifier n'apporte rien. Le refus de signer est
 * la seule chose qui ait de la valeur ici.
 *
 *   node witness.mjs --init --log https://origguard.com/api/v1 --name "Ton nom"
 *   node witness.mjs --log https://origguard.com/api/v1
 */
import fs from "node:fs";
import path from "node:path";

const args = process.argv.slice(2);
const opt = (n, d = null) => { const i = args.indexOf(n); return i >= 0 && args[i + 1] ? args[i + 1] : d; };
const LOG = (opt("--log", process.env.OVP_LOG) || "").replace(/\/$/, "");
const STATE = path.resolve(opt("--state", "witness-state.json"));
const OUT = path.resolve(opt("--out", "cosignature.json"));

const C = { g: "\x1b[32m", y: "\x1b[33m", r: "\x1b[31m", d: "\x1b[2m", b: "\x1b[1m", x: "\x1b[0m" };
const die = (m, h) => { console.error(`\n  ${C.r}✗ ${m}${C.x}${h ? `\n    ${C.d}${h}${C.x}` : ""}\n`); process.exit(1); };

/* ---------- primitives (OVP-1 §3, §4, §8) ---------- */
const b64 = (b) => Buffer.from(b).toString("base64");
const unb64 = (s) => new Uint8Array(Buffer.from(s, "base64"));
const unhex = (s) => Uint8Array.from(String(s).match(/.{2}/g) || [], (h) => parseInt(h, 16));
const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

function canonical(v) {
  if (v === null || v === undefined) return "null";
  if (typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  const k = Object.keys(v).filter((x) => v[x] !== undefined).sort();
  return `{${k.map((x) => `${JSON.stringify(x)}:${canonical(v[x])}`).join(",")}}`;
}
const sthBody = (sth) => { const { signatures, ...b } = sth; return canonical(b); };

const hashNode = async (l, r) => {
  const buf = new Uint8Array(1 + l.length + r.length);
  buf[0] = 0x01; buf.set(l, 1); buf.set(r, 1 + l.length);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
};
const isPow2 = (n) => n > 0 && (n & (n - 1)) === 0;

/** RFC 6962 §2.1.2 — l'ancien arbre est-il un préfixe du nouveau ? */
async function verifyConsistency(first, second, firstRoot, secondRoot, proof) {
  if (first > second) return false;
  if (first === second) return proof.length === 0 && hex(firstRoot) === hex(secondRoot);
  if (first === 0) return true;
  let fn = first - 1, sn = second - 1;
  while (fn & 1) { fn >>= 1; sn >>= 1; }
  let i = 0, fr, sr;
  if (isPow2(first)) { fr = firstRoot; sr = firstRoot; }
  else { if (!proof.length) return false; fr = proof[0]; sr = proof[0]; i = 1; }
  for (let j = i; j < proof.length; j++) {
    if (sn === 0) return false;
    if (fn & 1 || fn === sn) {
      fr = await hashNode(proof[j], fr); sr = await hashNode(proof[j], sr);
      while (fn !== 0 && !(fn & 1)) { fn >>= 1; sn >>= 1; }
    } else sr = await hashNode(sr, proof[j]);
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && hex(fr) === hex(firstRoot) && hex(sr) === hex(secondRoot);
}

async function verifySig(pubB64, sigB64, bytes) {
  try {
    const k = await crypto.subtle.importKey("raw", unb64(pubB64), { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, k, unb64(sigB64), bytes);
  } catch { return false; }
}

/* ---------- initialisation ---------- */
if (args.includes("--init")) {
  if (fs.existsSync(STATE)) die(`${STATE} existe déjà`, "Supprime-le d'abord si tu veux repartir de zéro.");
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const st = {
    name: opt("--name", "témoin sans nom"),
    log: LOG || null,
    publicKey: b64(await crypto.subtle.exportKey("raw", kp.publicKey)),
    privateKey: b64(await crypto.subtle.exportKey("pkcs8", kp.privateKey)),
    logPublicKey: null, lastTreeSize: null, lastRootHash: null, observations: 0,
  };
  fs.writeFileSync(STATE, JSON.stringify(st, null, 2), { mode: 0o600 });
  console.log(`\n  ${C.g}Témoin initialisé.${C.x}\n`);
  console.log(`  Ta clé publique, à communiquer à l'opérateur :\n    ${C.b}${st.publicKey}${C.x}\n`);
  console.log(`  ${C.y}${STATE} contient ta clé privée. Ne le partage pas, ne le versionne pas.${C.x}\n`);
  process.exit(0);
}

/* ---------- exécution ---------- */
if (!fs.existsSync(STATE)) die(`Aucun état trouvé (${STATE})`, "Lance d'abord : node witness.mjs --init --log <url> --name \"…\"");
const st = JSON.parse(fs.readFileSync(STATE, "utf8"));
const base = LOG || st.log;
if (!base) die("Aucune URL de journal", "Utilise --log https://…/api/v1");

const get = async (p) => {
  const r = await fetch(base + p);
  if (!r.ok) die(`${p} → HTTP ${r.status}`);
  return r.json();
};

const sth = await get("/tree/sth");
console.log(`\n  ${C.b}${st.name}${C.x} ${C.d}→ ${base}  ·  taille annoncée : ${sth.treeSize}${C.x}\n`);

// 1. clé du journal : épinglée à la première observation
const logSig = (sth.signatures || []).find((s) => s.role === "log");
if (!logSig) die("La tête d'arbre ne porte aucune signature du journal.");
if (st.logPublicKey && st.logPublicKey !== logSig.publicKey) {
  die("LA CLÉ DU JOURNAL A CHANGÉ.",
      "Une rotation de clé non annoncée est indiscernable d'une substitution. Ne cosigne pas. Contacte l'opérateur hors bande.");
}

// 2. signature du journal
if (!(await verifySig(logSig.publicKey, logSig.value, new TextEncoder().encode(sthBody(sth))))) {
  die("Signature du journal invalide.", "La tête d'arbre ne correspond pas à son contenu.");
}
console.log(`  ${C.g}✓${C.x} signature du journal valide`);

// 3. continuité depuis TA dernière observation — le cœur du rôle
let first = false;
if (st.lastTreeSize === null) {
  first = true;
  console.log(`  ${C.y}!${C.x} première observation : rien à comparer.`);
  console.log(`    ${C.d}La détection d'une réécriture ne commence qu'à partir de la prochaine.${C.x}`);
} else if (sth.treeSize < st.lastTreeSize) {
  die(`RÉGRESSION : ${sth.treeSize} entrées annoncées contre ${st.lastTreeSize} vues précédemment.`,
      "Des entrées ont disparu. Ne cosigne pas.");
} else if (sth.treeSize === st.lastTreeSize) {
  if (sth.rootHash !== st.lastRootHash) {
    die("RÉÉCRITURE : même taille, racine différente.", "L'historique a été modifié. Ne cosigne pas.");
  }
  console.log(`  ${C.g}✓${C.x} journal inchangé depuis ta dernière observation`);
} else {
  const cp = await get(`/tree/consistency?from=${st.lastTreeSize}&to=${sth.treeSize}`);
  const ok = await verifyConsistency(
    st.lastTreeSize, sth.treeSize, unhex(st.lastRootHash), unhex(sth.rootHash),
    (cp.proof || []).map(unhex),
  );
  if (!ok) {
    die(`RÉÉCRITURE : aucune preuve de consistance valide de ${st.lastTreeSize} vers ${sth.treeSize}.`,
        "L'historique que tu avais vu n'est pas un préfixe du nouveau. Ne cosigne pas — c'est précisément ce que ton rôle sert à détecter.");
  }
  console.log(`  ${C.g}✓${C.x} continuité vérifiée : ${st.lastTreeSize} → ${sth.treeSize} (+${sth.treeSize - st.lastTreeSize})`);
}

// 4. cosignature
const key = await crypto.subtle.importKey("pkcs8", unb64(st.privateKey), { name: "Ed25519" }, false, ["sign"]);
const value = b64(await crypto.subtle.sign({ name: "Ed25519" }, key, new TextEncoder().encode(sthBody(sth))));
const cosig = {
  role: "witness", name: st.name, alg: "Ed25519", publicKey: st.publicKey, value,
  observedAt: new Date().toISOString(), treeSize: sth.treeSize, rootHash: sth.rootHash,
  firstObservation: first || undefined,
};
fs.writeFileSync(OUT, JSON.stringify(cosig, null, 2));

st.logPublicKey = logSig.publicKey;
st.lastTreeSize = sth.treeSize;
st.lastRootHash = sth.rootHash;
st.observations = (st.observations || 0) + 1;
fs.writeFileSync(STATE, JSON.stringify(st, null, 2), { mode: 0o600 });

console.log(`\n  ${C.g}${C.b}Cosigné.${C.x} → ${path.basename(OUT)}  ${C.d}(observation n°${st.observations})${C.x}`);
console.log(`  ${C.d}Ta signature atteste que tu as observé cette tête d'arbre et vérifié sa continuité.`);
console.log(`  Elle ne dit rien du contenu du journal, ni du produit de l'opérateur.${C.x}\n`);
