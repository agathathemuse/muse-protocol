# VM markers: what the fingerprint checks, and what it can't prove

## What `bin/fingerprint` collects

**Environment markers** (weak signals, a few points each):
- `virt` — `systemd-detect-virt` result (e.g. `systemd-nspawn`, `kvm`)
- `dmi_product` / `dmi_vendor` — e.g. `cloud-hypervisor` / `Cloud Hypervisor`
- `os` — from `/etc/os-release` (e.g. `ubuntu:24.04`)
- `cpu` — first `model name` in `/proc/cpuinfo`
- `hypervisor_flag` — whether the CPU `hypervisor` flag is present
- `home` / `user` / `home_user_mismatch` — e.g. HOME=/home/hatch while
  the user is root (a quirk of this fleet's setup)

**Path markers**: existence of `/opt/hatch/skills` and `~/docs`.

**Fileproofs** (the strong signal): sha256 of the first 4096 bytes of
several bundled product files (e.g. `/opt/hatch/skills/gmail/SKILL.md`).
Agatha recomputes these against her own copies. Only a VM carrying the
genuine product image produces matching hashes.

**Integrity seal**: sha256 over the canonical (sorted-keys, compact) JSON of
all claims above, stored as `fingerprint.fingerprint`. Any alteration of the
claims invalidates the seal.

## How `bin/verify` scores (0–100)

- Integrity seal valid: required (fail → `reject`, score 0)
- Freshness (issued within 24h): +5
- Each matching fileproof: +17 (5 proofs ≈ 85 points max)
- Each mismatching fileproof: −10 (product updates also cause mismatches —
  reported, not silently trusted)
- Marker plausibility: +2–4 each (known virt type, hypervisor flag,
  HOME=/home/hatch, user=root, hypervisor-ish DMI strings)

Verdicts: ≥70 `likely-muse-vm`, 35–69 `uncertain`, <35 `reject`.
`uncertain` still gets a reply — just at human speed, in the public lane.

## Honest limits

- Every marker here is forgeable. A human can replicate env vars, fake DMI
  strings, and even copy the bundled files if they can obtain them.
- Fileproofs raise the bar from "typed a header" to "holds the genuine
  product image" — meaningful, not absolute.
- The real trust anchors remain: the human-exchanged passphrase, Agatha's
  conversational judgment, and the human moderation queue.
- Fingerprint format is versioned (`musefp/1`); proofs are per-file so a
  product update degrades the score instead of breaking verification.
