# DataProtector driver — XEDR modifications

Vendored from EDR-DataProtector (`DataProtector/`, `DataProtectorPolicyApi/` → `policyapi/`).
License: **GPL-3.0** (see `LICENSE`). Distributing `DataProtector.sys` means offering this
modified source under GPL-3.0. The XEDR agent talks to the driver only through the
Filter Manager port, as a separate program.

## Changes (2026-11-11)

| File | Change | Why |
| --- | --- | --- |
| `DpControl.c` | Message callback copies user buffers into non-paged kernel memory (`__try` + probe) and dispatches on the copies | The per-module query routines fill output under spin locks (DISPATCH_LEVEL); writing pageable user memory there can bugcheck |
| `DataProtector.h` | Default flags are audit-only for threat engine, static scan, hash protection, lateral defense; new `*_FLAG_AUDIT_ONLY` for hash/lateral | The reference defaults blocked LSASS/credential/hive/raw-disk access, SMB executable staging (breaks SCCM-style deployment) and auto-isolated hosts |
| `DpHashProtect.c`, `DpLateralDefense.c`, `DpUserHookDefense.c` | Honor audit-only: record the event, skip the deny (`Status=STATUS_SUCCESS` in events means audited) | Same; user-hook declared `AUDIT_ONLY` but never read it |
| `DpCrypto.c` (rewritten) | AES-256-CTR via kernel CNG; per-file key derived from a provisioned KEK + random file nonce; fails closed | The original was a fixed-key XOR "test provider" with the key written in plaintext into every file footer |
| `DpPolicy.c`, `DpShadow.c`, `DpIo.c`, `DpBuffer.c` | Single source of truth per file for its key (footer → stream context → handles); an existing footer key is never replaced; transform errors fail the I/O | With per-file keys, the original independent "default key" fetches would mix keys and corrupt data |
| `DpControl.c` | New commands 170 `SetCryptoKeys`, 171 `QueryCryptoStatus` (never returns key material) | Key provisioning from the agent |
| `build.ps1` | cl/link build without WDK MSBuild integration; `/we4013` | Implicit declarations silently truncate pointers on x64 |

## Encryption design

- KEK ring (≤ 8 AES-256 keys, by id) is pushed by the agent; lives only in non-paged memory.
  Without a KEK, protected I/O is denied (never plaintext, never garbage).
- File footer `FileKey` = `DP_FILE_KEY_BLOB` { magic `XEK1`, KEK id, check, nonce[16] } — no secret.
- Data key = `AES-ECB_KEK(nonce^1) || AES-ECB_KEK(nonce^2)`; check = `AES-ECB_KEK(nonce^3)[0:4]`.
- Data = AES-256-CTR, counter = LE uint64 block index (offset/16). Length-preserving, random access.
- Offline recovery: `agent/xedr-decrypt.exe -keys <export.json>`; keys exported by an admin via
  `POST /api/agent/driver-keys/export` (audited). Same scheme in `agent/xedrcrypt` (unit-tested).
- Known limit of any length-preserving per-offset scheme: rewriting the same offset of the same file
  reuses keystream, so someone holding two ciphertext versions of that file learns their XOR.

## Not yet verified — required before production

1. Load in a test VM (`bcdedit /set testsigning on`, reboot) with **Driver Verifier** on
   `DataProtector.sys` (standard + IRQL checking + pool tracking); exercise create/read/write/rename,
   Office save (shadow path), and the agent's event polling.
2. End-to-end crypto: protect a file through the driver, decrypt it with `xedr-decrypt`; reboot,
   confirm it stays readable after the agent re-pushes the KEK.
3. Production signing: EV certificate + Microsoft attestation; request an own minifilter altitude
   (141000 is the reference project's value in the encryption range).
