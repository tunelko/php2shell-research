# Credits and attribution

## Public exploit primitive

The original public PHP2Shell ASLR-bypass exploit primitive was created by
**9bie and contributors** in:

```text
https://github.com/9bie/php2shell-bypass-aslr-exp
```

This repository pins and fetches this exact upstream commit at runtime:

```text
4586f5cc120c82fd468b17469202bac629810ad9
```

The upstream repository currently has no explicit license. Therefore, this
repository does **not** redistribute or vendor that exploit source. `solver/`
only contains a bootstrap that clones the upstream repository and applies
documented runtime adaptations after checkout.

This repository's contribution is the authorized laboratory, fixed-proof
runner, profile dispatch, calibration tooling, request recording, shell bridge,
documentation, and tests—not the original exploit primitive.

## Vulnerability research and PHP fixes

The upstream PHP security advisories credit the following reporters for the two
PHP2Shell issues:

```text
lcfr-hax
sagitzadik-wiz
tomash-areion
amyb-oai
```

They also credit these PHP remediation developers:

```text
arnaud-lb
iluuu1994
bukka
ndossche
```

Official advisories:

```text
https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
```

## This repository

Laboratory design, profile engine, calibration workflow, solver integration,
request dumping, shell bridge, platform, documentation, and tests in this
repository are by **tunelko** and repository contributors.

Where runtime code is derived from or patches the upstream exploit, that
boundary is documented in `docs/upstream-changes.md`.
