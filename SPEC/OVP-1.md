# OVP-1 — Open Verification Protocol

**Version:** 1.0 (draft)
**Status:** Draft for implementation
**Editor:** Forges Emmanuel · ORIGGUARD · admin@origguard.com
**License:** This specification is published under CC BY 4.0. The reference implementation is licensed separately (Apache-2.0).

---

## Abstract

OVP defines two composable formats:

- **Part A — Operation Attestation.** A signed record proving that a local operation produced a given output, and that stated properties of that output hold. A verifier holding **only the output** can check it. The input is never required and never transmitted.
- **Part L — Transparency Log.** An append-only Merkle log binding software builds to public entries, such that rewriting history is detectable by any party that has previously observed the log.

Together they let one party prove a fact to another party that cannot see the data the fact is about.

## 1. Scope and non-goals

OVP addresses a narrow problem: **verifying a property of a result without disclosing the material that produced it.**

OVP does **not** provide: confidentiality of the output itself, proof that an input is authentic or "the real document", proof that the executing machine was not compromised, or any legal or regulatory status. Section 9 states these limits normatively — implementations are required to surface them.

## 2. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as described in RFC 2119.

All hashes are SHA-256 unless stated otherwise. Byte strings are represented in lowercase hexadecimal. Binary values inside JSON (signatures, keys) are base64 as defined in RFC 4648 §4, with padding.

Normative test vectors are provided in `test-vectors.json`. **An implementation that does not reproduce every test vector byte-for-byte is not conformant.**

## 3. Canonical serialization

Signatures and hashes are computed over a canonical serialization of JSON values. Two implementations MUST produce byte-identical output for the same value.

An implementation MUST serialize as follows:

1. **Absent fields are omitted.** A field whose value is absent (JavaScript `undefined`, a missing key, `None`) MUST NOT appear. `null` is a value and MUST be serialized as `null`.
2. **Objects**: keys sorted ascending by **UTF-16 code unit**; serialized as `{"k1":v1,"k2":v2}` with no whitespace.
3. **Arrays**: `[v1,v2]`, order preserved, no whitespace.
4. **Strings**: JSON string form with the escaping rules of ECMAScript `JSON.stringify` — `"` and `\` escaped, control characters below U+0020 escaped, all other characters emitted literally as UTF-8.
5. **Numbers**: the shortest round-tripping form, as produced by ECMAScript `Number::toString`. Implementations SHOULD avoid non-integer numbers in signed structures.
6. **Booleans**: `true` / `false`.

The output is encoded as **UTF-8** before hashing or signing.

> These rules align with RFC 8785 (JCS) for the value subset OVP uses. Conformance is defined by the test vectors, not by reference to JCS.

**Example** (test vector `unicode key sorting`):

```
{"é":1,"e":2,"Z":3,"a":4}   →   {"Z":3,"a":4,"e":2,"é":1}
```

## 4. Signatures

Signature algorithm: **Ed25519** (RFC 8032). Ed25519 is deterministic: a given key and message always yield the same signature, which makes signatures reproducible test vectors.

Public keys are the 32-byte raw form, base64-encoded.

---

# Part A — Operation Attestation

## 5. Structure

Media type: `application/ovp-attestation+json` · Suggested extension: `.ovp.json`

```json
{
  "v": 1,
  "type": "origguard.operation.attestation",
  "operation": {
    "name": "pdf-redaction",
    "at": "2026-08-28T10:31:00.000Z",
    "input":  { "sha256": "<hex>", "bytes": 123456 },
    "output": { "sha256": "<hex>", "bytes": 98765 }
  },
  "build": {
    "product": "Toolocal Redaction",
    "version": "1.4.0",
    "artifactSha256": "<hex>",
    "logEntry": "https://example/log/…"
  },
  "properties": [
    {
      "id": "no-incremental-revisions",
      "claim": "The file contains no recoverable earlier revision.",
      "method": "Count of %%EOF and startxref markers in the file bytes.",
      "result": "pass",
      "measured": "1 revision detected",
      "recheckable": true
    }
  ],
  "signature": { "alg": "Ed25519", "publicKey": "<base64>", "value": "<base64>" }
}
```

### 5.1 Field requirements

| Field | Req. | Notes |
|---|---|---|
| `v` | MUST | `1` for this version |
| `type` | MUST | exactly `origguard.operation.attestation` |
| `operation.name` | MUST | short stable identifier of the operation |
| `operation.at` | MUST | RFC 3339 UTC timestamp |
| `operation.input` | MAY be `null` | **only** `sha256` and `bytes`; never the content |
| `operation.output` | MUST | `sha256` and `bytes` of the produced artifact |
| `build.product`, `build.version` | MUST | |
| `build.artifactSha256` | SHOULD | digest of the software artifact that ran |
| `build.logEntry` | SHOULD | reference into a Part L log |
| `properties[]` | MUST (MAY be empty) | see §5.2 |
| `signature.alg` | MUST | `Ed25519` |
| `signature.publicKey` | MUST | base64 raw 32-byte key |
| `signature.value` | MUST | base64 signature |

### 5.2 Property objects

`id` (stable identifier), `claim` (what is asserted, in plain language), `method` (how it was determined — a verifier must be able to reimplement it from this string plus the specification of the checker), `result` (`pass` or `fail`), `measured` (the quantity observed, or `null`), `recheckable` (boolean).

`recheckable: true` means the property is **fully determined by the output bytes** and MUST be independently reproducible by any verifier holding the output.

**A producer MUST NOT emit an attestation containing a property whose `result` is `fail`.** Attesting a failed operation is a false statement; the operation is to be corrected, not attested.

## 6. Signing

1. Build the attestation object **without** `signature.value`, keeping `signature.alg` and `signature.publicKey`.
2. Canonicalize it (§3) and encode as UTF-8.
3. Sign those bytes with Ed25519.
4. Place the base64 signature in `signature.value`.

The signature therefore covers everything except itself, including the public key that verifies it.

## 7. Verification

A verifier is given an attestation and, optionally, the output bytes. It MUST perform, in order:

1. **Structure** — reject if `type` does not match or `v` is unknown.
2. **Signature** — recompute the signed body per §6 and verify. Failure ⇒ verdict `FAIL`.
3. **Issuer** — if a set of accepted public keys is supplied, the signing key MUST be a member. If none is supplied, the verifier MUST report issuer identity as *not established*.
4. **Output binding** — if output bytes are supplied, `sha256` MUST match. Mismatch ⇒ `FAIL`.
5. **Property recheck** — for every property with `recheckable: true`, if a checker is available the verifier MUST re-run it on the output bytes and compare.

### 7.1 The decisive rule

> **A valid signature MUST NOT override a failed recheck.**
>
> If a property is asserted `pass` and the verifier's own recheck yields `fail`, the verdict MUST be `FAIL`.

A signature establishes that a statement was not altered. It does not establish that the statement is true. A conformant verifier recomputes rather than believes. **An implementation that trusts asserted properties without rechecking them is not conformant.**

### 7.2 Reporting

A verifier MUST produce three distinct sections:

- **ESTABLISHED** — what was verified.
- **FAILURES** — what did not verify.
- **NOT ESTABLISHED** — what this verification does not cover.

The third section MUST be emitted **on every verification, including successful ones**, and MUST include at minimum the items of §9.1. A proof whose limits are unknown produces overconfidence, and overconfidence is worth less than no proof.

---

# Part L — Transparency Log

## 8. Merkle tree

OVP-1 uses the Merkle Tree Hash of RFC 6962 §2.1.

```
MTH({})     = SHA-256("")
MTH({d0})   = SHA-256(0x00 ‖ d0)
MTH(D[n])   = SHA-256(0x01 ‖ MTH(D[0:k]) ‖ MTH(D[k:n]))
              where k is the largest power of two strictly less than n
```

The `0x00` / `0x01` prefixes are **mandatory**. Without domain separation a leaf can be presented as an interior node, allowing a proof of inclusion for an entry that was never logged.

### 8.1 Entries

An entry is a JSON object. Its leaf hash is `SHA-256(0x00 ‖ UTF-8(canonical(entry)))` per §3. Entries SHOULD describe software builds:

```json
{ "product": "Toolocal Redaction", "version": "1.4.0",
  "artifactSha256": "<hex>", "checks": ["local-guard-strict","delivery-gate"],
  "addedAt": "2026-08-28T10:00:00.000Z" }
```

### 8.2 Signed Tree Head (STH)

```json
{ "v": 1, "type": "origguard.log.sth", "logId": "origguard-builds",
  "treeSize": 42, "rootHash": "<hex>", "at": "<RFC3339>",
  "signatures": [
    { "role": "log",     "alg": "Ed25519", "publicKey": "<b64>", "value": "<b64>" },
    { "role": "witness", "name": "…", "alg": "Ed25519", "publicKey": "<b64>", "value": "<b64>" }
  ] }
```

Every signature covers the canonicalization of the STH **excluding the `signatures` array entirely**. All signatures therefore cover identical bytes, and witnesses can co-sign without coordination.

An STH MUST carry exactly one `role: "log"` signature and MAY carry any number of `role: "witness"` signatures.

### 8.3 Proofs

Inclusion and consistency proofs are those of RFC 6962 §2.1.1 and §2.1.2. Verification algorithms are reproduced here for implementers; test vectors are normative.

**Inclusion** — verify that leaf `index` of a tree of size `treeSize` yields `root`:

```
fn ← index ; sn ← treeSize − 1 ; r ← leafHash
for each p in proof:
    if sn = 0: return false
    if (fn is odd) or (fn = sn):
        r ← H(0x01 ‖ p ‖ r)
        while fn ≠ 0 and fn is even: fn ← fn ≫ 1 ; sn ← sn ≫ 1
    else:
        r ← H(0x01 ‖ r ‖ p)
    fn ← fn ≫ 1 ; sn ← sn ≫ 1
return sn = 0 and r = root
```

**Consistency** — verify that a tree of size `first` is a prefix of one of size `second`:

```
if first > second: return false
if first = second: return proof is empty and firstRoot = secondRoot
if first = 0: return true

fn ← first − 1 ; sn ← second − 1
while fn is odd: fn ← fn ≫ 1 ; sn ← sn ≫ 1

if first is a power of two: fr ← firstRoot ; sr ← firstRoot ; i ← 0
else:                       if proof empty: return false
                            fr ← proof[0] ; sr ← proof[0] ; i ← 1

for j from i to len(proof) − 1:
    if sn = 0: return false
    if (fn is odd) or (fn = sn):
        fr ← H(0x01 ‖ proof[j] ‖ fr)
        sr ← H(0x01 ‖ proof[j] ‖ sr)
        while fn ≠ 0 and fn is even: fn ← fn ≫ 1 ; sn ← sn ≫ 1
    else:
        sr ← H(0x01 ‖ sr ‖ proof[j])
    fn ← fn ≫ 1 ; sn ← sn ≫ 1
return sn = 0 and fr = firstRoot and sr = secondRoot
```

## 9. Monitoring — the part that actually detects fraud

A single inclusion proof establishes nothing against the log operator: the operator holds the signing key and can sign any history.

**A conformant client MUST persist the last STH it accepted** (`treeSize`, `rootHash`) and, on every subsequent observation, MUST:

- reject if `treeSize` **decreased** — entries were removed;
- reject if `treeSize` is **unchanged but `rootHash` differs** — history was rewritten;
- if `treeSize` **grew**, require a consistency proof from the stored size to the new one and reject if it does not verify.

Only after acceptance may the stored STH be replaced.

**A client that verifies inclusion proofs but does not persist state across observations is not conformant.** It cannot detect rewriting, and offers only the appearance of verification.

### 9.1 Limitations — normative

An implementation MUST surface the following to the user, on every report:

1. **Input authenticity is not established.** Only the input digest is recorded. It permits proving the link *if* the input is later produced.
2. **Execution environment is not attested.** A compromised machine defeats all guarantees.
3. **Split view.** A log operator may serve different histories to different observers. Only independent witness co-signatures (§8.2) make this impractical, since fraud would require the complicity of all of them. An implementation MUST state when **no** witness co-signs.
4. **Detection begins at first observation.** History prior to a client's first stored STH is not covered by that client's own observation.
5. **Inclusion is not truth.** A log attests that something was recorded, not that its content is correct. Correctness of a result is Part A's concern.
6. **Static analysis is evadable.** Where a property is established by scanning code or bytes, obfuscation can hide the mechanism. Such properties SHOULD be paired with an enforcement mechanism (for example a browser Content-Security-Policy carried inside the hashed artifact), and the enforcement — not the scan — is what constitutes the guarantee.

## 10. Test vectors

`test-vectors.json` contains, generated by the reference implementation:

- **7 canonicalization vectors** — key ordering, nesting, `null`, Unicode key sorting, numbers, string escaping, empty containers. Each gives the exact canonical string and its SHA-256.
- **Merkle vectors** — 8 leaf inputs with their leaf hashes; roots for sizes 0–8; one inclusion proof (index 3 of 8); one consistency proof (5 → 8).
- **A signature example** — an Ed25519 key pair, a message, and the expected signature. Since Ed25519 is deterministic, a conformant implementation MUST reproduce this signature exactly.

An implementation claiming OVP-1 conformance MUST reproduce all of them.

## 11. Versioning

`v` is incremented for any change altering the bytes covered by a signature. Verifiers MUST reject unknown major versions rather than attempt best-effort interpretation.

## 12. Security considerations

Signing keys MUST NOT be committed to source control, written to build logs, or embedded in shipped artifacts. Log operators SHOULD publish complete entry lists so that any party can recompute the tree independently: **a log that cannot be replicated is not a public log.**

Independent witnesses SHOULD be recruited before the log is relied upon for any consequential decision. Until then, trust rests on the operator, and implementations MUST say so.

---

*Comments and independent implementations: admin@origguard.com*
