# Architecture notes

This expands on the README for readers who want the design rationale.

## Roles (RATS mapping)

The code maps directly onto IETF RATS ([RFC 9334](https://www.rfc-editor.org/rfc/rfc9334)):

| RATS role | Here |
|-----------|------|
| Attester | `cmd/workload` + `internal/attest` (produces Evidence) |
| Verifier | `internal/verify` (appraises Evidence against policy) |
| Relying Party | `internal/kbs` (acts on the appraisal: releases the key) |
| Reference Values | the measurement allowlist in `verify.Policy` |
| Endorsements | the pinned platform trust anchor (VCEK chain / test key) |

In this PoC the Verifier and Relying Party are colocated in the KBS, which is a
common deployment; they can be split without changing the protocol.

## The report and its bindings

`attest.Evidence` is a deliberately small analogue of a hardware report:

- `Measurement` — launch measurement of the guest image. Software backend:
  `SHA256("launch-digest:" + WORKLOAD_LAUNCH_DIGEST)`. SEV-SNP:
  `ATTESTATION_REPORT.MEASUREMENT`.
- `ReportData` — `SHA256(nonce ‖ pubkey)`. This is the crux of the design: the
  TEE signs the guest's ephemeral public key *and* the verifier's nonce into the
  report. A verified signature therefore proves "this specific key belongs to a
  guest that passed attestation under this specific challenge", which is what
  makes wrapping the secret to that key safe.
- `Signature` — over a length-prefixed canonical encoding of every other field
  (`internal/attest/canonical.go`), so no field boundary can be shifted.

## Appraisal order (fail-closed)

`verify.Appraise` runs checks cheapest-trust-first and returns on the first
failure; the KBS releases nothing unless it returns `nil`:

1. known TEE type with a pinned anchor;
2. signature valid under that anchor (authenticity);
3. nonce equals the issued one (freshness) — and the KBS separately enforces
   single-use + TTL, so a captured report cannot be replayed;
4. `report_data` binds the presented public key (anti key-substitution);
5. measurement in the allowlist (right code).

## Key release

On success the KBS wraps the application key with `RSA-OAEP(pubkey, key)`
(`internal/keyrelease`). Because `pubkey` was bound into a verified report, only
the guest instance that produced that report holds the matching private key and
can unwrap. The workload then uses the key to `AES-256-GCM`-open its sealed
config (`internal/seal`). The secret is never transmitted or stored in the
clear.

## Threat model (PoC scope)

Defended against, within the software backend:
- replay of a captured report (single-use nonce + TTL);
- substitution of the guest's public key to hijack the released secret
  (`report_data` binding);
- release to an unexpected image (measurement allowlist);
- tampering with any report field (signature over canonical encoding).

Out of scope (needs real hardware / production KBS):
- authenticity of the platform signing key (software backend uses a test key,
  not a vendor-rooted VCEK);
- physical / hypervisor attacks that TEE memory encryption addresses;
- production key management (HSM, rotation, audit).
