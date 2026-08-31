/**
 * Vérification côté client — et surveillance.
 *
 * Une preuve d'inclusion isolée ne prouve rien contre l'opérateur du journal :
 * il pourrait maintenir deux historiques et servir à chacun celui qui l'arrange.
 * Ce qui rend une réécriture DÉTECTABLE, c'est de conserver la dernière tête
 * d'arbre vue et d'exiger, à chaque consultation suivante, une preuve de
 * consistance depuis celle-ci.
 *
 * C'est le rôle du moniteur.
 */
import { verifyInclusion, verifyConsistency, hashLeaf, unhex, hex } from "./merkle.mjs";
import { verify as verifySig } from "./keys.mjs";
import { canonical, STH_TYPE } from "./log.mjs";

const enc = new TextEncoder();

/** Valide une tête d'arbre : structure + toutes les signatures présentes. */
export async function verifySTH(sth, { trustedLogKeys = [], trustedWitnessKeys = [] } = {}) {
  const out = { valid: false, logSigned: false, witnesses: [], issues: [] };
  if (!sth || sth.type !== STH_TYPE) { out.issues.push("Ce n'est pas une tête d'arbre OrigGuard."); return out; }
  const { signatures = [], ...body } = sth;
  const bytes = enc.encode(canonical(body));

  for (const s of signatures) {
    const good = await verifySig(s.publicKey, s.value, bytes);
    if (!good) { out.issues.push(`Signature ${s.role}${s.name ? ` (${s.name})` : ""} invalide.`); continue; }
    if (s.role === "log") {
      out.logSigned = true;
      if (trustedLogKeys.length && !trustedLogKeys.includes(s.publicKey)) out.issues.push("Le journal signe avec une clé non approuvée.");
    } else {
      out.witnesses.push(s.name || "témoin");
      if (trustedWitnessKeys.length && !trustedWitnessKeys.includes(s.publicKey)) out.issues.push(`Témoin ${s.name} non approuvé.`);
    }
  }
  if (!out.logSigned) out.issues.push("Aucune signature valide du journal.");
  out.valid = out.issues.length === 0;
  return out;
}

/** Vérifie qu'une entrée précise est bien dans l'arbre décrit par la tête. */
export async function verifyEntryInclusion(entry, { index, proof }, sth) {
  if (Number(sth.treeSize) !== Number(arguments[1].treeSize ?? sth.treeSize)) { /* toléré */ }
  const leaf = await hashLeaf(enc.encode(canonical(entry)));
  return verifyInclusion(index, sth.treeSize, leaf, proof.map(unhex), unhex(sth.rootHash));
}

/**
 * Moniteur — conserve la dernière tête vue et exige la continuité.
 * `state` est sérialisable : à conserver côté client entre deux exécutions.
 */
export function createMonitor(state = null) {
  let last = state;
  return {
    get state() { return last; },

    /**
     * @param sth       la nouvelle tête d'arbre présentée par le journal
     * @param getProof  (oldSize, newSize) => tableau d'empreintes hex
     */
    async check(sth, getProof, opts = {}) {
      const r = { accepted: false, reasons: [], firstSight: !last };
      const v = await verifySTH(sth, opts);
      if (!v.valid) { r.reasons.push(...v.issues); return r; }

      if (!last) {
        last = { treeSize: sth.treeSize, rootHash: sth.rootHash, at: sth.at };
        r.accepted = true;
        r.reasons.push("Première consultation : tête enregistrée. La détection d'une réécriture ne commence qu'à partir de maintenant.");
        r.witnesses = v.witnesses;
        return r;
      }

      if (sth.treeSize < last.treeSize) {
        r.reasons.push(`RÉGRESSION : le journal annonce ${sth.treeSize} entrées alors qu'il en avait ${last.treeSize}. Des entrées ont été retirées.`);
        return r;
      }
      if (sth.treeSize === last.treeSize) {
        if (sth.rootHash !== last.rootHash) {
          r.reasons.push("RÉÉCRITURE : même taille, racine différente. L'historique a été modifié.");
          return r;
        }
        r.accepted = true; r.reasons.push("Journal inchangé depuis la dernière consultation.");
        return r;
      }

      const proof = (await getProof(last.treeSize, sth.treeSize)).map(unhex);
      const ok = await verifyConsistency(last.treeSize, sth.treeSize, unhex(last.rootHash), unhex(sth.rootHash), proof);
      if (!ok) {
        r.reasons.push(`RÉÉCRITURE : aucune preuve de consistance valide de ${last.treeSize} vers ${sth.treeSize}. L'historique connu n'est pas un préfixe du nouveau.`);
        return r;
      }
      last = { treeSize: sth.treeSize, rootHash: sth.rootHash, at: sth.at };
      r.accepted = true;
      r.reasons.push(`Continuité vérifiée : ${sth.treeSize - (r.firstSight ? 0 : proof.length && last.treeSize)} nouvelle(s) entrée(s), l'historique n'a pas été modifié.`);
      r.witnesses = v.witnesses;
      return r;
    },
  };
}

/** Les limites, énoncées à chaque rapport — jamais optionnelles. */
export function limitations({ witnesses = [] } = {}) {
  const L = [
    "Une preuve d'inclusion isolée n'exclut pas qu'un opérateur serve deux historiques différents à deux personnes (vue divisée).",
    "Seule la conservation de la dernière tête d'arbre, consultation après consultation, rend une réécriture détectable.",
  ];
  if (witnesses.length === 0) {
    L.push("Aucun témoin indépendant ne cosigne cette tête : la vue divisée reste possible. Ajoutez des cosignataires tiers.");
  } else {
    L.push(`Cosignée par : ${witnesses.join(", ")}. La vue divisée exigerait la complicité de tous.`);
  }
  L.push("Le journal atteste que quelque chose a été inscrit, pas que ce contenu soit vrai.");
  return L;
}
