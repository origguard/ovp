/**
 * Journal public append-only.
 *
 * Stocké en fichiers plats et publiable sur n'importe quel hébergement
 * statique : n'importe qui peut le recopier intégralement et l'auditer.
 * Un journal que personne ne peut recopier n'est pas un journal public.
 */
import fs from "node:fs/promises";
import path from "node:path";
import { hashLeaf, merkleRoot, inclusionPath, consistencyPath, hex, unhex } from "./merkle.mjs";
import { sign } from "./keys.mjs";

const enc = new TextEncoder();
export const STH_TYPE = "origguard.log.sth";

export function canonical(v) {
  if (v === null || v === undefined) return "null";
  if (typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  const k = Object.keys(v).filter((x) => v[x] !== undefined).sort();
  return `{${k.map((x) => `${JSON.stringify(x)}:${canonical(v[x])}`).join(",")}}`;
}

export async function openLog(dir) {
  await fs.mkdir(dir, { recursive: true });
  const P = { entries: path.join(dir, "entries.jsonl"), meta: path.join(dir, "log.json"), sth: path.join(dir, "sth.json") };

  const readEntries = async () => {
    try {
      const raw = await fs.readFile(P.entries, "utf8");
      return raw.split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
    } catch { return []; }
  };
  const leavesOf = (entries) => Promise.all(entries.map((e) => hashLeaf(enc.encode(canonical(e)))));

  return {
    dir,
    async init({ logId, publicKey }) {
      await fs.writeFile(P.meta, JSON.stringify({ v: 1, logId, publicKey, createdAt: new Date().toISOString() }, null, 2));
      return this;
    },
    async meta() { return JSON.parse(await fs.readFile(P.meta, "utf8")); },
    async size() { return (await readEntries()).length; },
    async entries() { return readEntries(); },

    /**
     * Ajoute une entrée. Le journal REFUSE une entrée qui casserait sa propre
     * consistance — la garantie append-only est imposée à l'écriture, pas
     * seulement contrôlée après coup.
     */
    async append(entry) {
      const before = await readEntries();
      const beforeRoot = await merkleRoot(await leavesOf(before));
      const line = canonical({ ...entry, addedAt: entry.addedAt || new Date().toISOString() });
      await fs.appendFile(P.entries, line + "\n", "utf8");
      const after = await readEntries();
      const afterLeaves = await leavesOf(after);
      const cp = await consistencyPath(before.length, afterLeaves);
      const { verifyConsistency } = await import("./merkle.mjs");
      const okay = before.length === 0
        ? true
        : await verifyConsistency(before.length, after.length, beforeRoot, await merkleRoot(afterLeaves), cp);
      if (!okay) throw new Error("Ajout refusé : la consistance du journal serait rompue.");
      return { index: after.length - 1, size: after.length };
    },

    /** Tête d'arbre signée : la seule chose qu'un client doit retenir. */
    async signSTH(privateKey) {
      const m = await this.meta();
      const entries = await readEntries();
      const root = await merkleRoot(await leavesOf(entries));
      const body = {
        v: 1, type: STH_TYPE, logId: m.logId,
        treeSize: entries.length, rootHash: hex(root), at: new Date().toISOString(),
      };
      const sth = { ...body, signatures: [{ role: "log", alg: "Ed25519", publicKey: m.publicKey, value: await sign(privateKey, enc.encode(canonical(body))) }] };
      await fs.writeFile(P.sth, JSON.stringify(sth, null, 2));
      return sth;
    },

    /** Cosignature par un témoin indépendant — la parade à la vue divisée. */
    async addWitness(sth, { name, privateKey, publicKey }) {
      const { signatures, ...body } = sth;
      const value = await sign(privateKey, enc.encode(canonical(body)));
      const out = { ...sth, signatures: [...signatures, { role: "witness", name, alg: "Ed25519", publicKey, value }] };
      await fs.writeFile(P.sth, JSON.stringify(out, null, 2));
      return out;
    },

    async lastSTH() { try { return JSON.parse(await fs.readFile(P.sth, "utf8")); } catch { return null; } },

    async inclusionProof(index) {
      const entries = await readEntries();
      if (index < 0 || index >= entries.length) throw new Error("index hors du journal");
      const leaves = await leavesOf(entries);
      return {
        index, treeSize: entries.length, entry: entries[index],
        leafHash: hex(leaves[index]),
        proof: (await inclusionPath(index, leaves)).map(hex),
        rootHash: hex(await merkleRoot(leaves)),
      };
    },

    async consistencyProof(oldSize) {
      const entries = await readEntries();
      const leaves = await leavesOf(entries);
      return {
        oldSize, newSize: entries.length,
        proof: (await consistencyPath(oldSize, leaves)).map(hex),
        rootHash: hex(await merkleRoot(leaves)),
      };
    },

    /** Recalcule tout depuis les entrées brutes : l'audit complet d'un tiers. */
    async recomputeRoot() {
      return hex(await merkleRoot(await leavesOf(await readEntries())));
    },
  };
}
