#!/usr/bin/env node
/**
 * ogattest — produire et vérifier des attestations d'opération locale.
 *
 *   ogattest keygen                                     > cles.json
 *   ogattest attest --in original.pdf --out caviarde.pdf \
 *                   --keys cles.json --product "Toolocal Caviardage" \
 *                   --version 1.4.0 [--artifact <sha256>] [--log <url>]
 *                   > caviarde.pdf.ogatt.json
 *   ogattest verify --file caviarde.pdf --att caviarde.pdf.ogatt.json [--key <b64>]
 *
 * La commande `verify` n'a JAMAIS besoin du fichier d'origine.
 */
import fs from "node:fs/promises";
import { generateKeyPair } from "../src/keys.mjs";
import { createAttestation } from "../src/attest.mjs";
import { verifyAttestation, formatReport } from "../src/verify.mjs";
import { recheckPdf } from "../src/checkers/pdf.mjs";

const args = process.argv.slice(2);
const cmd = args[0];
const opt = (n, d = null) => { const i = args.indexOf(n); return i >= 0 && args[i + 1] ? args[i + 1] : d; };
const read = async (p) => new Uint8Array(await fs.readFile(p));

try {
  if (cmd === "keygen") {
    console.log(JSON.stringify(await generateKeyPair(), null, 2));
  } else if (cmd === "attest") {
    const outPath = opt("--out"), inPath = opt("--in"), keysPath = opt("--keys");
    if (!outPath || !keysPath) throw new Error("--out et --keys sont requis");
    const keys = JSON.parse(await fs.readFile(keysPath, "utf8"));
    const outputBytes = await read(outPath);
    const inputBytes = inPath ? await read(inPath) : null;

    const properties = recheckPdf(outputBytes);
    const failed = properties.filter((p) => p.result === "fail");
    if (failed.length) {
      console.error(`\nRefus d'attester : ${failed.length} propriété(s) en échec sur la sortie.`);
      failed.forEach((p) => console.error(`  ✗ ${p.id} — ${p.measured}`));
      console.error("\nAttester une opération dont une propriété échoue reviendrait à signer une fausse déclaration.\n");
      process.exit(1);
    }
    const att = await createAttestation({
      operation: { name: opt("--operation", "pdf-redaction"), inputBytes, outputBytes },
      build: {
        product: opt("--product", "Produit inconnu"), version: opt("--version", "0.0.0"),
        artifactSha256: opt("--artifact"), logEntry: opt("--log"),
      },
      properties, privateKey: keys.privateKey, publicKey: keys.publicKey,
    });
    console.log(JSON.stringify(att, null, 2));
  } else if (cmd === "verify") {
    const att = JSON.parse(await fs.readFile(opt("--att"), "utf8"));
    const filePath = opt("--file");
    const bytes = filePath ? await read(filePath) : null;
    const trustedKeys = opt("--key") ? [opt("--key")] : [];
    const r = await verifyAttestation(att, bytes, { trustedKeys, recheck: recheckPdf });
    console.log("\n" + formatReport(r) + "\n");
    process.exit(r.verdict === "CONFORME" ? 0 : 1);
  } else {
    console.log("Usage : ogattest keygen | attest --in <orig> --out <sortie> --keys <cles.json> | verify --file <sortie> --att <att.json> [--key <b64>]");
    process.exit(cmd ? 1 : 0);
  }
} catch (e) {
  console.error("Erreur :", e.message);
  process.exit(1);
}
