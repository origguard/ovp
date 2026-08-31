/**
 * Arbre de Merkle — RFC 6962 (Certificate Transparency).
 *
 * Deux préfixes distincts séparent les domaines :
 *   feuille = SHA-256(0x00 ‖ donnée)
 *   nœud    = SHA-256(0x01 ‖ gauche ‖ droite)
 *
 * Sans cette séparation, une feuille peut être présentée comme un nœud interne :
 * on prouve alors l'inclusion d'une entrée qui n'a jamais été ajoutée.
 */
const cat = (...arrs) => {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
};
const sha = async (bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));

export const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
export const unhex = (s) => Uint8Array.from(s.match(/.{2}/g) || [], (h) => parseInt(h, 16));

export const hashLeaf = (data) => sha(cat(new Uint8Array([0x00]), data));
export const hashNode = (l, r) => sha(cat(new Uint8Array([0x01]), l, r));
export const emptyRoot = () => sha(new Uint8Array(0));

/** Plus grande puissance de deux STRICTEMENT inférieure à n. */
function splitPoint(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** Racine d'une liste d'empreintes de feuilles. */
export async function merkleRoot(leaves) {
  if (leaves.length === 0) return emptyRoot();
  if (leaves.length === 1) return leaves[0];
  const k = splitPoint(leaves.length);
  return hashNode(await merkleRoot(leaves.slice(0, k)), await merkleRoot(leaves.slice(k)));
}

/** Chemin d'inclusion de la feuille `m` dans un arbre de `leaves`. */
export async function inclusionPath(m, leaves) {
  const n = leaves.length;
  if (n <= 1) return [];
  const k = splitPoint(n);
  return m < k
    ? [...(await inclusionPath(m, leaves.slice(0, k))), await merkleRoot(leaves.slice(k))]
    : [...(await inclusionPath(m - k, leaves.slice(k))), await merkleRoot(leaves.slice(0, k))];
}

/** Preuve que l'arbre de taille `m` est un PRÉFIXE de l'arbre courant. */
export async function consistencyPath(m, leaves) {
  if (m === 0 || m > leaves.length) return [];
  if (m === leaves.length) return [];
  return subProof(m, leaves, true);
}

async function subProof(m, leaves, b) {
  const n = leaves.length;
  if (m === n) return b ? [] : [await merkleRoot(leaves)];
  const k = splitPoint(n);
  return m <= k
    ? [...(await subProof(m, leaves.slice(0, k), b)), await merkleRoot(leaves.slice(k))]
    : [...(await subProof(m - k, leaves.slice(k), false)), await merkleRoot(leaves.slice(0, k))];
}

/** Vérifie une preuve d'inclusion sans détenir l'arbre. */
export async function verifyInclusion(index, treeSize, leafHash, proof, root) {
  if (index >= treeSize) return false;
  let fn = index, sn = treeSize - 1, r = leafHash;
  for (const p of proof) {
    if (sn === 0) return false;
    if (fn & 1 || fn === sn) {
      r = await hashNode(p, r);
      while (fn !== 0 && !(fn & 1)) { fn >>= 1; sn >>= 1; }
    } else {
      r = await hashNode(r, p);
    }
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && hex(r) === hex(root);
}

const isPow2 = (n) => n > 0 && (n & (n - 1)) === 0;

/**
 * Vérifie qu'un ancien état est bien un préfixe du nouveau.
 * C'est CETTE fonction qui rend une réécriture d'historique détectable.
 */
export async function verifyConsistency(first, second, firstRoot, secondRoot, proof) {
  if (first > second) return false;
  if (first === second) return proof.length === 0 && hex(firstRoot) === hex(secondRoot);
  if (first === 0) return true;

  let fn = first - 1, sn = second - 1;
  while (fn & 1) { fn >>= 1; sn >>= 1; }

  let idx = 0, fr, sr;
  if (isPow2(first)) { fr = firstRoot; sr = firstRoot; }
  else {
    if (proof.length === 0) return false;
    fr = proof[0]; sr = proof[0]; idx = 1;
  }

  for (let i = idx; i < proof.length; i++) {
    if (sn === 0) return false;
    if (fn & 1 || fn === sn) {
      fr = await hashNode(proof[i], fr);
      sr = await hashNode(proof[i], sr);
      while (fn !== 0 && !(fn & 1)) { fn >>= 1; sn >>= 1; }
    } else {
      sr = await hashNode(sr, proof[i]);
    }
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && hex(fr) === hex(firstRoot) && hex(sr) === hex(secondRoot);
}
