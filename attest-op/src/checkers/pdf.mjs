/**
 * Contrôles revérifiables sur un PDF — sur la SORTIE SEULE, sans dépendance.
 *
 * Chacun correspond à un échec de caviardage réellement survenu dans le monde :
 * des documents « caviardés » d'où le texte original a été récupéré.
 */
const txt = (bytes) => new TextDecoder("latin1").decode(bytes);

/**
 * L'échec de caviardage le plus courant : on pose des rectangles noirs et on
 * enregistre en mode incrémental. La révision précédente — avec le texte
 * intact — reste dans le fichier et se récupère en quelques secondes.
 */
export function noIncrementalRevisions(bytes) {
  const s = txt(bytes);
  const eof = (s.match(/%%EOF/g) || []).length;
  const startxref = (s.match(/startxref/g) || []).length;
  const revisions = Math.max(eof, startxref);
  return {
    id: "no-incremental-revisions",
    claim: "Le fichier ne contient aucune révision antérieure récupérable.",
    method: "Comptage des marqueurs %%EOF et startxref dans les octets du fichier.",
    result: revisions <= 1 ? "pass" : "fail",
    measured: `${revisions} révision(s) détectée(s)`,
    recheckable: true,
  };
}

/** Un fichier joint peut contenir l'original entier. */
export function noEmbeddedFiles(bytes) {
  const s = txt(bytes);
  const n = (s.match(/\/EmbeddedFile/g) || []).length;
  return {
    id: "no-embedded-files",
    claim: "Aucun fichier n'est joint au document.",
    method: "Recherche de /EmbeddedFile dans les octets du fichier.",
    result: n === 0 ? "pass" : "fail",
    measured: `${n} pièce(s) jointe(s)`,
    recheckable: true,
  };
}

/** Du JavaScript embarqué peut reconstituer ou exfiltrer du contenu à l'ouverture. */
export function noJavaScript(bytes) {
  const s = txt(bytes);
  const n = (s.match(/\/JavaScript|\/JS\b/g) || []).length;
  return {
    id: "no-javascript",
    claim: "Le document ne contient aucun JavaScript.",
    method: "Recherche de /JavaScript et /JS dans les octets du fichier.",
    result: n === 0 ? "pass" : "fail",
    measured: `${n} occurrence(s)`,
    recheckable: true,
  };
}

/**
 * Absence littérale de termes.
 *
 * ATTENTION : n'utiliser ce contrôle que si le vérificateur a légitimement
 * connaissance des termes (un tribunal qui sait ce qui devait être caviardé).
 * Ne JAMAIS écrire les termes dans l'attestation : elle est destinée à circuler.
 */
export function absenceOfTerms(bytes, terms = []) {
  const s = txt(bytes).toLowerCase();
  const found = terms.filter((t) => s.includes(String(t).toLowerCase()));
  return {
    id: "absence-of-terms",
    claim: "Les termes fournis n'apparaissent pas dans les octets du fichier.",
    method: "Recherche littérale, insensible à la casse, sur l'intégralité du fichier.",
    result: found.length === 0 ? "pass" : "fail",
    measured: `${terms.length} terme(s) contrôlé(s), ${found.length} trouvé(s)`,
    recheckable: true,
  };
}

export const PDF_CHECKERS = {
  "no-incremental-revisions": noIncrementalRevisions,
  "no-embedded-files": noEmbeddedFiles,
  "no-javascript": noJavaScript,
};

/** Rejoue tous les contrôles sans secret sur une sortie. */
export function recheckPdf(bytes) {
  return Object.values(PDF_CHECKERS).map((fn) => fn(bytes));
}
