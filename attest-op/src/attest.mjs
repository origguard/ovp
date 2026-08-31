/**
 * Attestation d'opération locale.
 *
 * Le principe : on ne prouve pas qu'une donnée n'est jamais sortie — c'est une
 * preuve d'absence, impossible. On prouve trois présences dont l'absence
 * découle :
 *
 *   1. le binaire qui a produit la sortie est identifié et publiquement attesté
 *   2. la sortie est exactement celle qui a été produite
 *   3. les propriétés annoncées sont REVÉRIFIABLES sur la sortie seule
 *
 * Conséquence : un tiers qui ne détient QUE la sortie peut tout contrôler,
 * sans jamais voir l'entrée.
 */
import { canonicalize, sha256Hex } from "./canonical.mjs";
import { sign } from "./keys.mjs";

export const ATTESTATION_VERSION = 1;
export const ATTESTATION_TYPE = "origguard.operation.attestation";

/** Corps signé : tout sauf la valeur de signature elle-même. */
export function signedBody(att) {
  const { signature, ...rest } = att;
  return canonicalize({ ...rest, signature: signature ? { alg: signature.alg, publicKey: signature.publicKey } : undefined });
}

export async function createAttestation({
  operation,            // { name, inputBytes, outputBytes, at? }
  build,                // { product, version, artifactSha256, logEntry? }
  properties = [],      // [{ id, claim, method, result, measured, recheckable }]
  privateKey,
  publicKey,
}) {
  if (!operation?.name) throw new Error("operation.name requis");
  if (!operation.outputBytes) throw new Error("operation.outputBytes requis");
  if (!build?.product || !build?.version) throw new Error("build.product et build.version requis");
  if (!privateKey || !publicKey) throw new Error("paire de clés requise");

  for (const p of properties) {
    if (!p.id || !p.claim || !p.method) throw new Error(`propriété incomplète : ${p.id || "(sans id)"}`);
    if (!["pass", "fail"].includes(p.result)) throw new Error(`résultat invalide pour ${p.id}`);
    // Une propriété annoncée en échec ne doit pas être attestée en silence.
    if (p.result === "fail") throw new Error(`propriété en échec : ${p.id} — ne pas attester une opération dont une propriété a échoué`);
  }

  const att = {
    v: ATTESTATION_VERSION,
    type: ATTESTATION_TYPE,
    operation: {
      name: operation.name,
      at: operation.at || new Date().toISOString(),
      // L'entrée n'est présente que par son empreinte : elle n'est jamais
      // transmise, et le vérificateur n'en a pas besoin.
      input: operation.inputBytes
        ? { sha256: await sha256Hex(operation.inputBytes), bytes: operation.inputBytes.byteLength }
        : null,
      output: { sha256: await sha256Hex(operation.outputBytes), bytes: operation.outputBytes.byteLength },
    },
    build: {
      product: build.product,
      version: build.version,
      artifactSha256: build.artifactSha256 || null,
      logEntry: build.logEntry || null,
    },
    properties: properties.map((p) => ({
      id: p.id, claim: p.claim, method: p.method,
      result: p.result, measured: p.measured || null,
      recheckable: p.recheckable === true,
    })),
    signature: { alg: "Ed25519", publicKey },
  };

  att.signature.value = await sign(privateKey, new TextEncoder().encode(signedBody(att)));
  return att;
}
