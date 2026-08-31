/**
 * Ed25519 via WebCrypto — disponible dans Node 18+, Chrome, Firefox et les
 * WebViews récentes. Le vérificateur peut donc tourner partout, y compris
 * dans une page hors-ligne.
 */
import { b64, unb64 } from "./canonical.mjs";

export async function generateKeyPair() {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  return {
    publicKey: b64(await crypto.subtle.exportKey("raw", kp.publicKey)),      // 32 octets
    privateKey: b64(await crypto.subtle.exportKey("pkcs8", kp.privateKey)),
  };
}

export const importPrivate = (b) =>
  crypto.subtle.importKey("pkcs8", unb64(b), { name: "Ed25519" }, false, ["sign"]);
export const importPublic = (b) =>
  crypto.subtle.importKey("raw", unb64(b), { name: "Ed25519" }, false, ["verify"]);

export async function sign(privateKeyB64, bytes) {
  const k = await importPrivate(privateKeyB64);
  return b64(await crypto.subtle.sign({ name: "Ed25519" }, k, bytes));
}

/** Ne lève jamais : une clé ou une signature malformée renvoie false. */
export async function verify(publicKeyB64, signatureB64, bytes) {
  try {
    const k = await importPublic(publicKeyB64);
    return await crypto.subtle.verify({ name: "Ed25519" }, k, unb64(signatureB64), bytes);
  } catch {
    return false;
  }
}
