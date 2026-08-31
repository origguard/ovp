import { generateKeyPair } from "../src/keys.mjs";
import { createAttestation, signedBody } from "../src/attest.mjs";
import { verifyAttestation } from "../src/verify.mjs";
import { recheckPdf, absenceOfTerms } from "../src/checkers/pdf.mjs";
import { canonicalize } from "../src/canonical.mjs";

let pass = 0, fail = 0;
const ok = (n, c, x = "") => { c ? (pass++, console.log(`PASS - ${n}`)) : (fail++, console.log(`FAIL - ${n}${x ? ` :: ${x}` : ""}`)); };
const bytes = (s) => new TextEncoder().encode(s);

// PDF « propre » : une seule révision, ni pièce jointe ni JavaScript.
const PDF_OK = bytes("%PDF-1.7\n1 0 obj<</Type/Page>>endobj\nxref\ntrailer<</Size 2>>\nstartxref\n120\n%%EOF\n");
// PDF « caviardé » à la va-vite : la révision d'origine est toujours là.
const PDF_INCR = bytes("%PDF-1.7\nORIGINAL Durand 4200\nstartxref\n90\n%%EOF\n2 0 obj<</Rect[0 0 100 20]>>endobj\nstartxref\n200\n%%EOF\n");

const keys = await generateKeyPair();
const mkAtt = (outputBytes, inputBytes = bytes("original secret")) =>
  createAttestation({
    operation: { name: "pdf-redaction", inputBytes, outputBytes },
    build: { product: "Toolocal Caviardage", version: "1.4.0", artifactSha256: "abc123", logEntry: "https://exemple/log/1" },
    properties: recheckPdf(outputBytes), privateKey: keys.privateKey, publicKey: keys.publicKey,
  });

console.log("\n=== 1. Le vérificateur n'a JAMAIS besoin de l'entrée ===");
{
  const att = await mkAtt(PDF_OK);
  const r = await verifyAttestation(att, PDF_OK, { trustedKeys: [keys.publicKey], recheck: recheckPdf });
  ok("verdict CONFORME sans l'original", r.verdict === "CONFORME", r.failures.join("|"));
  ok("la sortie est reconnue", r.established.some((e) => e.includes("exactement celui")));
  ok("l'entrée n'est présente que par empreinte", /^[0-9a-f]{64}$/.test(att.operation.input.sha256));
  ok("le contenu de l'entrée n'apparaît nulle part", !JSON.stringify(att).includes("original secret"));
}

console.log("\n=== 2. Les propriétés sont REJOUÉES, pas crues sur parole ===");
{
  const att = await mkAtt(PDF_OK);
  const r = await verifyAttestation(att, PDF_OK, { trustedKeys: [keys.publicKey], recheck: recheckPdf });
  ok("au moins 3 propriétés rejouées", r.established.filter((e) => e.includes("REJOUÉE")).length >= 3);
  // Un producteur malhonnête annonce « conforme » sur un fichier qui ne l'est pas.
  const menteur = await createAttestation({
    operation: { name: "pdf-redaction", outputBytes: PDF_INCR },
    build: { product: "X", version: "1" },
    properties: [{ id: "no-incremental-revisions", claim: "aucune révision", method: "comptage", result: "pass", measured: "1 révision", recheckable: true }],
    privateKey: keys.privateKey, publicKey: keys.publicKey,
  });
  const r2 = await verifyAttestation(menteur, PDF_INCR, { trustedKeys: [keys.publicKey], recheck: recheckPdf });
  ok("une fausse déclaration est INFIRMÉE au contrôle", r2.verdict === "ÉCHEC" && r2.failures.some((f) => f.includes("INFIRMÉE")));
}

console.log("\n=== 3. Refus d'attester une opération non conforme ===");
{
  let refus = false;
  try {
    await createAttestation({
      operation: { name: "x", outputBytes: PDF_INCR }, build: { product: "X", version: "1" },
      properties: recheckPdf(PDF_INCR), privateKey: keys.privateKey, publicKey: keys.publicKey,
    });
  } catch (e) { refus = /échec/i.test(e.message); }
  ok("attester un caviardage raté est refusé à la source", refus);
}

console.log("\n=== 4. Toute altération est détectée ===");
{
  const att = await mkAtt(PDF_OK);
  const modifie = JSON.parse(JSON.stringify(att));
  modifie.build.version = "9.9.9";
  const r = await verifyAttestation(modifie, PDF_OK, { trustedKeys: [keys.publicKey], recheck: recheckPdf });
  ok("attestation modifiée -> signature invalide", r.verdict === "ÉCHEC" && r.failures.some((f) => f.includes("Signature invalide")));

  const autre = bytes("%PDF-1.7\nautre fichier\nstartxref\n1\n%%EOF\n");
  const r2 = await verifyAttestation(att, autre, { trustedKeys: [keys.publicKey], recheck: recheckPdf });
  ok("fichier substitué -> détecté", r2.verdict === "ÉCHEC" && r2.failures.some((f) => f.includes("NE correspond PAS")));

  const r3 = await verifyAttestation(att, PDF_OK, { trustedKeys: ["AAAA"], recheck: recheckPdf });
  ok("clé non approuvée -> signalée", r3.verdict === "ÉCHEC" && r3.failures.some((f) => f.includes("PAS dans la liste")));
}

console.log("\n=== 5. Le vérificateur énonce toujours ses limites ===");
{
  const att = await mkAtt(PDF_OK);
  const r = await verifyAttestation(att, PDF_OK, { trustedKeys: [keys.publicKey], recheck: recheckPdf });
  ok("l'entrée non prouvée est déclarée", r.notEstablished.some((n) => n.includes("ENTRÉE")));
  ok("la machine non attestée est déclarée", r.notEstablished.some((n) => n.includes("compromise")));
  ok("le journal public à contrôler est déclaré", r.notEstablished.some((n) => n.includes("journal public")));
  const r2 = await verifyAttestation(att, PDF_OK, { recheck: recheckPdf });
  ok("sans clé approuvée, l'émetteur est déclaré non établi", r2.notEstablished.some((n) => n.includes("identité de l'émetteur")));
}

console.log("\n=== 6. Détection réelle des échecs de caviardage ===");
{
  const p = recheckPdf(PDF_INCR);
  ok("révision antérieure détectée", p.find((x) => x.id === "no-incremental-revisions").result === "fail");
  const joint = bytes("%PDF\n/EmbeddedFile 1 0 R\nstartxref\n1\n%%EOF");
  ok("pièce jointe détectée", recheckPdf(joint).find((x) => x.id === "no-embedded-files").result === "fail");
  const js = bytes("%PDF\n/JavaScript (app.alert)\nstartxref\n1\n%%EOF");
  ok("JavaScript détecté", recheckPdf(js).find((x) => x.id === "no-javascript").result === "fail");
  ok("texte résiduel détecté par absenceOfTerms", absenceOfTerms(PDF_INCR, ["Durand"]).result === "fail");
  ok("aucun faux positif sur un fichier propre", recheckPdf(PDF_OK).every((x) => x.result === "pass"));
}

console.log("\n=== 7. Canonicité : la signature ne dépend pas de l'ordre des clés ===");
{
  const att = await mkAtt(PDF_OK);
  const permute = JSON.parse(JSON.stringify({ signature: att.signature, operation: att.operation, build: att.build, properties: att.properties, type: att.type, v: att.v }));
  ok("corps signé identique malgré l'ordre", signedBody(att) === signedBody(permute));
  const r = await verifyAttestation(permute, PDF_OK, { trustedKeys: [keys.publicKey], recheck: recheckPdf });
  ok("vérification toujours CONFORME", r.verdict === "CONFORME", r.failures.join("|"));
  ok("canonicalize trie en profondeur", canonicalize({ b: { d: 1, c: 2 }, a: 3 }) === '{"a":3,"b":{"c":2,"d":1}}');
}

console.log(`\n${"=".repeat(46)}\nRÉSULTAT : ${pass} succès, ${fail} échec(s)`);
process.exit(fail ? 1 : 0);
