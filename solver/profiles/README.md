# PHP profile inventory

The generated full table is available in `INVENTORY.md`.

Calibration is organizer-only and runs against disposable local Docker images.
A profile is enabled by the remote solver only when both `verified` and `rce`
are true.

| PHP | Image | Disclosure | RCE | Enabled |
|---|---|---|---|---|
| 8.0.30 amd64 | `php:8.0.30-apache` | failed | not reached | no |
| 8.1.34 amd64 | `php:8.1.34-apache` | failed | not reached | no |
| 8.2.34 amd64 | `php:8.2.34-apache` | failed | not reached | no |
| 8.3.35 amd64/aarch64 | `php:8.3.35-apache` | heap + libphp leaks | not verified | no |
| 8.5.0 aarch64 | `php:8.5.0-apache` | heap + libphp leaks | not verified | no |
| 8.4.25 aarch64 | `php:8.4.25-apache` | heap + libphp leaks | verified | yes |
| 8.4.26 amd64 | `php:8.4.26-apache` | heap + libphp leaks | verified | yes |
| 8.5.10 aarch64 | `php:8.5.10-apache` | heap + libphp leaks | verified | yes |
| 8.5.11 aarch64 | `php:8.5.11-apache` | heap + libphp leaks | verified | yes |
| 8.5.11 amd64 | `php:8.5.11-apache` | heap + libphp leaks | verified | yes |

The current primitive is not version-generic. PHP 8.0–8.2 need a new stage-1
layout and PHP 8.3 needs a new stage-3 carrier/layout. Profiles for another
architecture or distribution cannot be reused just because the version string
matches.
