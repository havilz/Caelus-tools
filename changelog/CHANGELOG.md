# Changelog

All notable changes to the Caelus Cloud project are documented here.

Entries follow formal conventions with explicit timestamps `[YYYY-MM-DD HH:mm:ss]`.

---

## [Unreleased]

### [2026-09-07 12:40:00] - Sentinel Closed-Loop Remediation & State Deduplication

- **Database Deduplication Migration (`000017_fix_security_findings_deduplication`, `000018_add_ssh_hardened_to_servers`)**:
  - Replaced partial fingerprint index with unconditional `NULLS NOT DISTINCT` unique index to eliminate duplicate finding creation.
  - Added `ssh_hardened` boolean flag to servers table to persist host security posture.
  - Updated PostgreSQL `UpsertFinding` conflict clause to preserve `resolved` and `false_positive` states on routine scans.
- **Closed-Loop Telemetry & Verification Subsystem**:
  - Added live SSH daemon inspection (`checkSSHHardening`) to agent Linux collector inspecting `/etc/ssh/sshd_config`.
  - Hooked `CAELUS-FIREWALL` into `DOCKER-USER` chain to prevent Docker container port bypass on Linux hosts.
  - Updated `HostConfigScanner` and `VulnScanner` to eliminate false positives and only report findings when real policy violations exist.
  - Added `ReopenFinding` and `ReverifyFinding` endpoints on backend API and client services.
- **Frontend Dashboard Enhancements**:
  - Added quick status filter pill buttons (All, Open, Resolved) to Sentinel security hub.
  - Added interactive "Verifikasi Ulang" and "Buka Kembali" actions in `FindingDetailModal.tsx`.
  - Removed glass backdrop blur effects from modals.
