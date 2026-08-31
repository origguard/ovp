#!/usr/bin/env node
/**
 * oglog — journal public append-only.
 *
 *   oglog init   --dir ./log --id origguard-builds --keys cles.json
 *   oglog append --dir ./log --keys cles.json --product "Toolocal" --version 1.4.0 --artifact <sha256>
 *   oglog sth    --dir ./log --keys cles.json
 *   oglog prove  --dir ./log --index 3
 *   oglog audit  --dir ./log --state moniteur.json --key <pub>
 */
import fs from "node:fs/promises";
import { openLog } from "../src/log.mjs";
import { generateKeyPair } from "../src/keys.mjs";
import { verifySTH, verifyEntryInclusion, createMonitor, limitations } from "../src/monitor.mjs";

const a = process.argv.slice(2), cmd = a[0];
const opt = (n, d = null) => { const i = a.indexOf(n); return i >= 0 && a[i + 1] ? a[i + 1] : d; };
const dir = opt("--dir", "./log");
const keys = async () => JSON.parse(await fs.readFile(opt("--keys"), "utf8"));

try {
  if (cmd === "keygen") console.log(JSON.stringify(await generateKeyPair(), null, 2));
  else if (cmd === "init") {
    const k = await keys();
    await (await openLog(dir)).init({ logId: opt("--id", "origguard-log"), publicKey: k.publicKey });
    console.log(`Journal initialisé dans ${dir}`);
  } else if (cmd === "append") {
    const log = await openLog(dir), k = await keys();
    const r = await log.append({
      product: opt("--product"), version: opt("--version"),
      artifactSha256: opt("--artifact"), checks: (opt("--checks", "") || "").split(",").filter(Boolean),
    });
    const sth = await log.signSTH(k.privateKey);
    console.log(`Inscrit à l'index ${r.index}. Taille : ${sth.treeSize}. Racine : ${sth.rootHash.slice(0, 24)}…`);
  } else if (cmd === "sth") {
    console.log(JSON.stringify(await (await openLog(dir)).signSTH((await keys()).privateKey), null, 2));
  } else if (cmd === "prove") {
    console.log(JSON.stringify(await (await openLog(dir)).inclusionProof(Number(opt("--index", "0"))), null, 2));
  } else if (cmd === "audit") {
    const log = await openLog(dir);
    const statePath = opt("--state", "moniteur.json");
    let state = null; try { state = JSON.parse(await fs.readFile(statePath, "utf8")); } catch {}
    const mon = createMonitor(state);
    const sth = await log.lastSTH();
    if (!sth) throw new Error("aucune tête d'arbre publiée");
    const r = await mon.check(sth, async (old) => (await log.consistencyProof(old)).proof,
      { trustedLogKeys: opt("--key") ? [opt("--key")] : [] });
    const v = await verifySTH(sth, {});
    console.log(`\n${r.accepted ? "ACCEPTÉ" : "REJETÉ"} — taille ${sth.treeSize}`);
    r.reasons.forEach((x) => console.log(`  ${r.accepted ? "·" : "✗"} ${x}`));
    console.log("\nLIMITES — toujours affichées");
    limitations({ witnesses: v.witnesses }).forEach((l) => console.log(`  · ${l}`));
    console.log("");
    if (r.accepted) await fs.writeFile(statePath, JSON.stringify(mon.state, null, 2));
    process.exit(r.accepted ? 0 : 1);
  } else {
    console.log("Usage : oglog keygen | init | append | sth | prove | audit");
    process.exit(cmd ? 1 : 0);
  }
} catch (e) { console.error("Erreur :", e.message); process.exit(1); }
