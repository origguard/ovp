/**
 * Sérialisation canonique — la fondation de tout le reste.
 *
 * Une signature ne vaut que si les deux parties sérialisent EXACTEMENT de la
 * même façon. Sans ordre canonique, deux représentations du même objet
 * produisent deux signatures différentes, et la vérification échoue sans
 * qu'aucune fraude n'ait eu lieu.
 */
export function canonicalize(value) {
  if (value === null || value === undefined) return "null";
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(",")}}`;
}

export async function sha256Hex(bytes) {
  const h = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
export const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
