# OVP — Open Verification Protocol

**Prove a property of a result without disclosing the material that produced it.**

> **OVP is an open protocol. OrigGuard is its first implementation and log operator.**

A third party receives only your output file. They can verify that the stated transformation really happened, that the file hasn't changed, and which software produced it — **without ever seeing your source document.**

| Directory | What it is |
|---|---|
| [SPEC/OVP-1.md](SPEC/OVP-1.md) | The normative specification. Implementable in any language. |
| [SPEC/test-vectors.json](SPEC/test-vectors.json) | Normative test vectors. An implementation that doesn't reproduce them is not conformant. |
| [ttest-op/](attest-op/) | Reference implementation — produce and verify operation attestations. |
| [	ranslog/](translog/) | Append-only Merkle log (RFC 6962). Rewriting history is detectable by anyone. |
| [witness/](witness/) | Single-file, zero-dependency witness. Co-signs a log — and **refuses** when the history was rewritten. |

## The idea in one paragraph

You cannot prove that data never left a machine — that's a proof of absence over an open future. So OVP doesn't try. It establishes three presences from which the absence follows: the impossibility is **mechanical** (a Content-Security-Policy inside the hashed artifact), the binary is **identified** (a signed digest in a public append-only log), and the result is **re-derivable** (properties are replayed on the output alone).

No theorem is broken. One unsolvable question is replaced by three solvable ones.

## The rule that makes it different from a certificate

> **A valid signature MUST NOT override a failed recheck.**

A signature proves a statement wasn't altered. It does not prove the statement is true. A conformant verifier recomputes rather than believes — see OVP-1 §7.1.

## Honest limits

Every implementation must surface them, on every report, including successful ones: input authenticity is not established, the execution environment is not attested, a single-operator log permits a split view until independent witnesses co-sign, detection begins at first observation, and static analysis is evadable — enforcement, not scanning, is the guarantee.

See OVP-1 §9.1.

## Status

Draft, v1.0. Two independent implementations have already produced byte-identical canonical serializations against the same signature. Comments and independent implementations very welcome: admin@origguard.com

## Tests

`ash
cd attest-op && npm test     # 22 checks
cd translog  && npm test     # 17 checks, plus 1,122 exhaustive Merkle proofs
`

## Related

- [local-guard](https://github.com/origguard/local-guard) — Verify that a built web artifact cannot exfiltrate user data.
- [localsync](https://github.com/origguard/localsync) — Zero-server multi-device synchronization engine.
- [OrigGuard Verification Portal](https://app.origguard.com/verify) — Production web verifier.

## License

Apache-2.0 for the code. The specification is CC BY 4.0.
