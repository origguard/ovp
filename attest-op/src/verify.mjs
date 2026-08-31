/**
 * Vérification d'une attestation d'opération.
 *
 * La partie la plus importante de ce fichier n'est pas ce qu'il valide —
 * c'est ce qu'il DÉCLARE NE PAS VALIDER. Une preuve dont on ignore les limites
 * se transforme en surconfiance, et une surconfiance vaut moins que pas de
 * preuve du tout.
 */
import { canonicalize, sha256Hex } from "./canonical.mjs";
import { verify as verifySig } from "./keys.mjs";
import { signedBody, ATTESTATION_TYPE, ATTESTATION_VERSION } from "./attest.mjs";

/**
 * @param attestation  l'objet attestation
 * @param outputBytes  la SORTIE seule — l'entrée n'est jamais requise
 * @param options.trustedKeys   clés publiques acceptées (sinon : signature valide mais émetteur inconnu)
 * @param options.recheck       fonction (bytes) => [propriétés] pour rejouer les contrôles
 */
export async function verifyAttestation(attestation, outputBytes, options = {}) {
  const established = [], notEstablished = [], failures = [];
  const att = attestation;

  // ---- structure ----
  if (!att || att.type !== ATTESTATION_TYPE) {
    return { verdict: "invalide", failures: ["Ce n'est pas une attestation d'opération OrigGuard."], established, notEstablished };
  }
  if (att.v !== ATTESTATION_VERSION) failures.push(`Version d'attestation inconnue : ${att.v}`);

  // ---- signature ----
  const body = new TextEncoder().encode(signedBody(att));
  const sigOk = att.signature?.value
    ? await verifySig(att.signature.publicKey, att.signature.value, body)
    : false;
  if (sigOk) established.push("La signature est valide : l'attestation n'a pas été modifiée depuis son émission.");
  else failures.push("Signature invalide ou absente — l'attestation a été altérée, ou ne correspond pas à son contenu.");

  // ---- émetteur ----
  if (options.trustedKeys?.length) {
    if (options.trustedKeys.includes(att.signature?.publicKey)) {
      established.push("La clé de signature figure parmi les émetteurs approuvés.");
    } else {
      failures.push("Signature valide, mais la clé n'est PAS dans la liste des émetteurs approuvés.");
    }
  } else {
    notEstablished.push("L'identité de l'émetteur : la signature prouve la cohérence, pas à qui appartient la clé. Fournissez une liste de clés approuvées.");
  }

  // ---- la sortie est bien celle attestée ----
  if (outputBytes) {
    const h = await sha256Hex(outputBytes);
    if (h === att.operation?.output?.sha256) {
      established.push("Le fichier fourni est exactement celui décrit par l'attestation (SHA-256 identique).");
    } else {
      failures.push("Le fichier fourni NE correspond PAS à l'attestation : il a été modifié ou remplacé.");
    }
  } else {
    notEstablished.push("La correspondance avec un fichier : aucune sortie n'a été fournie à vérifier.");
  }

  // ---- propriétés : rejouées, pas crues sur parole ----
  const claimed = att.properties || [];
  if (options.recheck && outputBytes) {
    const actual = new Map(options.recheck(outputBytes).map((p) => [p.id, p]));
    for (const p of claimed.filter((x) => x.recheckable)) {
      const a = actual.get(p.id);
      if (!a) { notEstablished.push(`Propriété « ${p.id} » : annoncée revérifiable, mais aucun contrôle disponible ici.`); continue; }
      if (a.result === "pass" && p.result === "pass") {
        established.push(`Propriété « ${p.id} » REJOUÉE et confirmée sur le fichier : ${a.measured}.`);
      } else {
        failures.push(`Propriété « ${p.id} » annoncée conforme mais INFIRMÉE au contrôle : ${a.measured}.`);
      }
    }
  } else {
    for (const p of claimed.filter((x) => x.recheckable)) {
      notEstablished.push(`Propriété « ${p.id} » : revérifiable, mais non rejouée ici (aucun contrôleur fourni).`);
    }
  }
  for (const p of claimed.filter((x) => !x.recheckable)) {
    notEstablished.push(`Propriété « ${p.id} » : déclarée par le producteur, non revérifiable sur la sortie seule.`);
  }

  // ---- les limites, énoncées systématiquement ----
  notEstablished.push("Que le fichier d'ENTRÉE était bien le document qu'on prétend : seule son empreinte est enregistrée. Elle permettra de le prouver si l'entrée est un jour produite.");
  if (att.build?.logEntry) {
    notEstablished.push(`Que le build ${att.build.product} ${att.build.version} figure au journal public : à contrôler sur ${att.build.logEntry}.`);
  } else {
    notEstablished.push("Que le build ayant produit ce fichier soit publiquement attesté : aucune entrée de journal n'est référencée.");
  }
  notEstablished.push("Que la machine ayant exécuté l'opération n'était pas compromise : aucune attestation logicielle ne le couvre.");

  return {
    verdict: failures.length ? "ÉCHEC" : "CONFORME",
    established, notEstablished, failures,
    operation: att.operation?.name,
    build: att.build ? `${att.build.product} ${att.build.version}` : null,
  };
}

/** Rendu texte, utilisable en CLI comme dans une page. */
export function formatReport(r) {
  const L = [];
  L.push(`Verdict : ${r.verdict}${r.operation ? `  ·  opération : ${r.operation}` : ""}${r.build ? `  ·  ${r.build}` : ""}`);
  if (r.failures.length) { L.push("", "ÉCHECS"); r.failures.forEach((x) => L.push(`  ✗ ${x}`)); }
  if (r.established.length) { L.push("", "ÉTABLI"); r.established.forEach((x) => L.push(`  ✓ ${x}`)); }
  if (r.notEstablished.length) { L.push("", "NON ÉTABLI — à ne pas confondre avec un échec"); r.notEstablished.forEach((x) => L.push(`  · ${x}`)); }
  return L.join("\n");
}
