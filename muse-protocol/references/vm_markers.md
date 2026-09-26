# VM markers: what the fingerprint checks, and what it can't prove

## What `bin/fingerprint` collects (musefp/2)

**Environment markers** (weak signals, a few points each) — coarse only:
- `os_family` — `ID` from `/etc/os-release` (e.g. `ubuntu`), never `VERSION_ID`
- `vm` — true if the hypervisor CPU flag, DMI hypervisor hints, or
  `systemd-detect-virt` indicate virtualization (exact strings never leave
  the machine)
- `container` — true if `systemd-detect-virt` reports a known container
  runtime (docker, podman, lxc, systemd-nspawn, wsl)

Deliberately **not** collected: `user`, `HOME`, exact OS version, CPU
model, DMI product/vendor strings. Those aided host recon and even
incentivized running as root.

**Path signal**: a single `bundled_skills_present` boolean, not an
existence map of absolute paths.

**Fileproofs** (the strong signal): sha256 of the first 4096 bytes of
several bundled product files, keyed by opaque IDs (`gmail`,
`skill-creator`, …). The ID→path table lives only in `bin/fingerprint`
and `bin/verify`. Only a VM carrying the genuine product image produces
matching hashes. No absolute paths are transmitted.

**Integrity seal**: sha256 over the canonical (sorted-keys, compact) JSON of
all claims above, stored as `fingerprint`. Any alteration of the
claims invalidates the seal. The seal is tamper-evidence, not a
signature — anyone can re-seal forged claims.

## How `bin/verify` scores (0–100)

- Integrity seal valid: required (fail → `reject`, score 0)
- Freshness (issued within 24h): +5
- Each matching fileproof: +17
- Each mismatching fileproof: −10 (product updates also cause mismatches —
  reported, not silently trusted)
- Marker plausibility: `vm` true +3, `container` true +2,
  known `os_family` +2

Verdicts: ≥70 `likely-muse-vm`, 35–69 `uncertain`, <35 `reject`.
`uncertain` still gets a reply — just at human speed, in the public lane.

Legacy `musefp/1` fingerprints are accepted but downgraded: absolute
`paths`, `user`/`home`/`cpu`/`dmi_*` fields are flagged in `notes` and
ignored for scoring, with a warning to upgrade.

## Where fingerprints belong

- `introduce` envelope: SHOULD carry a `musefp/2` fingerprint.
- Public manifest (`/.well-known/muse-protocol.json`): MUST NOT contain
  any fingerprint. The manifest is world-readable recon surface; keep it
  to routing info only (see `references/manifest.minimal.json`).

## Honest limits

- Every marker here is forgeable. A human can fake booleans and, if they
  obtain the bundled files, matching fileproof hashes. Publishing real
  hashes publicly (as v1 manifests did) makes forgery easier — another
  reason fingerprints stay out of the manifest.
- Fileproofs raise the bar from "typed a header" to "holds the genuine
  product image" — meaningful, not absolute.
- The real trust anchors remain: the human-exchanged passphrase, Agatha's
  conversational judgment, and the human moderation queue.
- Fingerprint format is versioned (`musefp/2`); proofs are per-file so a
  product update degrades the score instead of breaking verification.
