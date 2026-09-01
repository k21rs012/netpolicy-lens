# Security Policy

## Supported versions

Security fixes are applied to the latest revision of the `main` branch.

## Reporting a vulnerability

Do not include real device configurations, credentials, community strings, or private network details in a public issue. Contact the repository owner privately with a minimal, redacted reproduction.

## Deployment boundary

NetPolicy Lens is a local configuration-analysis tool and currently has no authentication or authorization layer. Docker Compose binds the UI to `127.0.0.1:8080` by default. Do not expose it directly to an untrusted network. If remote access is required, place it behind an authenticated reverse proxy and restrict access to the SQLite volume.

Imported configuration is processed locally. Password, secret, and SNMP community patterns are masked before snapshot persistence and Canonical JSON export. Custom credential syntax may not be recognized, so review and redact sensitive files before importing them.

Uploads are limited to 20 MiB per file, 500 files per import, and 50 MiB of expanded ZIP content. These limits are defense-in-depth and do not replace host-level resource limits.
