import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { openLog, canonical } from "../src/log.mjs";
import { generateKeyPair } from "../src/keys.mjs";
import { verifySTH, verifyEntryInclusion, createMonitor, limitations } from "../src/monitor.mjs";
import { merkleRoot, hashLeaf, verifyInclusion, unhex } from "../src/merkle.mjs";

let pass = 0, fail = 0;
const ok = (n, c, x = "") => { c ? (pass++, console.log(`PASS - ${n}`)) : (fail++, console.log(`FAIL - ${n}${x ? ` :: ${x}` : ""}`)); };
const tmp = async () => fs.mkdtemp(path.join(os.tmpdir(), "translog-"));

const logKeys = await generateKeyPair();
const witKeys = await generateKeyPair();
const mkEntry = (v) => ({ product: "Toolocal Caviardage", version: v, artifactSha256: `sha-${v}`, checks: ["local-guard-strict", "delivery-gate"] });

console.log("\n=== 1. Ajout et inclusion ===");
{
  const dir = await tmp();
  const log = await (await openLog(dir)).init({ logId: "origguard-builds", publicKey: logKeys.publicKey });
  for (const v of ["1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0"]) await log.append(mkEntry(v));
  ok("5 entrées inscrites", (await log.size()) === 5);
  const sth = await log.signSTH(logKeys.privateKey);
  ok("tête d'arbre signée", (await verifySTH(sth, { trustedLogKeys: [logKeys.publicKey] })).valid);
  const p = await log.inclusionProof(3);
  ok("inclusion vérifiée sur la tête seule", await verifyEntryInclusion(p.entry, p, sth));
  await fs.rm(dir, { recursive: true, force: true });
}

console.log("\n=== 2. Un tiers recalcule tout depuis les entrées brutes ===");
{
  const dir = await tmp();
  const log = await (await openLog(dir)).init({ logId: "l", publicKey: logKeys.publicKey });
  for (let i = 0; i < 9; i++) await log.append(mkEntry(`2.${i}.0`));
  const sth = await log.signSTH(logKeys.privateKey);
  const entries = await log.entries();
  const leaves = await Promise.all(entries.map((e) => hashLeaf(new TextEncoder().encode(canonical(e)))));
  const recomputed = await merkleRoot(leaves);
  ok("racine recalculée identique à la tête signée", [...recomputed].map((b) => b.toString(16).padStart(2, "0")).join("") === sth.rootHash);
  await fs.rm(dir, { recursive: true, force: true });
}

console.log("\n=== 3. LE test : une réécriture est détectée ===");
{
  const dir = await tmp();
  const log = await (await openLog(dir)).init({ logId: "l", publicKey: logKeys.publicKey });
  for (let i = 0; i < 4; i++) await log.append(mkEntry(`3.${i}.0`));
  const sth1 = await log.signSTH(logKeys.privateKey);

  const mon = createMonitor();
  const r1 = await mon.check(sth1, async (a, b) => (await log.consistencyProof(a)).proof, { trustedLogKeys: [logKeys.publicKey] });
  ok("première consultation acceptée", r1.accepted && r1.firstSight);

  await log.append(mkEntry("3.5.0"));
  const sth2 = await log.signSTH(logKeys.privateKey);
  const r2 = await mon.check(sth2, async (a) => (await log.consistencyProof(a)).proof, { trustedLogKeys: [logKeys.publicKey] });
  ok("ajout légitime accepté", r2.accepted, r2.reasons.join("|"));

  // L'opérateur réécrit l'historique : il retire une entrée et en ajoute une autre.
  const entries = await log.entries();
  entries.splice(1, 1);
  entries.push(mkEntry("3.9.0"));
  await fs.writeFile(path.join(dir, "entries.jsonl"), entries.map(canonical).join("\n") + "\n");
  const sthFraude = await log.signSTH(logKeys.privateKey);

  const r3 = await mon.check(sthFraude, async (a) => (await log.consistencyProof(a)).proof, { trustedLogKeys: [logKeys.publicKey] });
  ok("RÉÉCRITURE DÉTECTÉE malgré une signature valide", !r3.accepted && r3.reasons.some((x) => /RÉÉCRITURE/.test(x)), r3.reasons.join("|"));
  ok("la tête frauduleuse est pourtant bien signée", (await verifySTH(sthFraude, { trustedLogKeys: [logKeys.publicKey] })).valid);
  await fs.rm(dir, { recursive: true, force: true });
}

console.log("\n=== 4. Suppression d'entrées : régression détectée ===");
{
  const dir = await tmp();
  const log = await (await openLog(dir)).init({ logId: "l", publicKey: logKeys.publicKey });
  for (let i = 0; i < 6; i++) await log.append(mkEntry(`4.${i}.0`));
  const sth1 = await log.signSTH(logKeys.privateKey);
  const mon = createMonitor();
  await mon.check(sth1, async (a) => (await log.consistencyProof(a)).proof, { trustedLogKeys: [logKeys.publicKey] });

  const e = await log.entries();
  await fs.writeFile(path.join(dir, "entries.jsonl"), e.slice(0, 3).map(canonical).join("\n") + "\n");
  const sth2 = await log.signSTH(logKeys.privateKey);
  const r = await mon.check(sth2, async (a) => (await log.consistencyProof(a)).proof, { trustedLogKeys: [logKeys.publicKey] });
  ok("RÉGRESSION détectée", !r.accepted && r.reasons.some((x) => /RÉGRESSION/.test(x)));
  await fs.rm(dir, { recursive: true, force: true });
}

console.log("\n=== 5. Même taille, racine différente : substitution détectée ===");
{
  const dir = await tmp();
  const log = await (await openLog(dir)).init({ logId: "l", publicKey: logKeys.publicKey });
  for (let i = 0; i < 4; i++) await log.append(mkEntry(`5.${i}.0`));
  const sth1 = await log.signSTH(logKeys.privateKey);
  const mon = createMonitor();
  await mon.check(sth1, async (a) => (await log.consistencyProof(a)).proof, { trustedLogKeys: [logKeys.publicKey] });

  const e = await log.entries();
  e[2] = mkEntry("5.2.0-MODIFIE");
  await fs.writeFile(path.join(dir, "entries.jsonl"), e.map(canonical).join("\n") + "\n");
  const sth2 = await log.signSTH(logKeys.privateKey);
  const r = await mon.check(sth2, async (a) => (await log.consistencyProof(a)).proof, { trustedLogKeys: [logKeys.publicKey] });
  ok("substitution à taille égale détectée", !r.accepted && r.reasons.some((x) => /RÉÉCRITURE/.test(x)));
  await fs.rm(dir, { recursive: true, force: true });
}

console.log("\n=== 6. Témoins et vue divisée ===");
{
  const dir = await tmp();
  const log = await (await openLog(dir)).init({ logId: "l", publicKey: logKeys.publicKey });
  await log.append(mkEntry("6.0.0"));
  let sth = await log.signSTH(logKeys.privateKey);
  ok("sans témoin, la limite est annoncée", limitations({ witnesses: [] }).some((l) => /vue divisée reste possible/.test(l)));
  sth = await log.addWitness(sth, { name: "Observatoire tiers", privateKey: witKeys.privateKey, publicKey: witKeys.publicKey });
  const v = await verifySTH(sth, { trustedLogKeys: [logKeys.publicKey], trustedWitnessKeys: [witKeys.publicKey] });
  ok("cosignature de témoin validée", v.valid && v.witnesses.includes("Observatoire tiers"));
  ok("avec témoin, la limite change", limitations({ witnesses: v.witnesses }).some((l) => /complicité de tous/.test(l)));
  const faux = JSON.parse(JSON.stringify(sth));
  faux.treeSize = 99;
  ok("tête altérée -> toutes signatures invalides", !(await verifySTH(faux, { trustedLogKeys: [logKeys.publicKey] })).valid);
  await fs.rm(dir, { recursive: true, force: true });
}

console.log("\n=== 7. Clé non approuvée et limites systématiques ===");
{
  const dir = await tmp();
  const autre = await generateKeyPair();
  const log = await (await openLog(dir)).init({ logId: "l", publicKey: logKeys.publicKey });
  await log.append(mkEntry("7.0.0"));
  const sth = await log.signSTH(logKeys.privateKey);
  const v = await verifySTH(sth, { trustedLogKeys: [autre.publicKey] });
  ok("clé de journal non approuvée -> signalée", !v.valid && v.issues.some((i) => /non approuvée/.test(i)));
  const L = limitations({ witnesses: [] });
  ok("la vue divisée est toujours énoncée", L.some((l) => /vue divisée/.test(l)));
  ok("« inscrit ≠ vrai » est toujours énoncé", L.some((l) => /pas que ce contenu soit vrai/.test(l)));
  await fs.rm(dir, { recursive: true, force: true });
}

console.log(`\n${"=".repeat(46)}\nRÉSULTAT : ${pass} succès, ${fail} échec(s)`);
process.exit(fail ? 1 : 0);
