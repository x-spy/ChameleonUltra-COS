# Security Policy

## Supported Scope

Security reports for this repository should relate to the ChameleonUltra-COS fork and its modifications, including COS emulation behavior, CLI commands, storage handling, APDU handling, and firmware integration introduced by this fork.

Issues in the upstream Chameleon Ultra project should also be reported to the upstream maintainers when they are not specific to this fork.

## Reporting a Vulnerability

Do not open a public issue with exploit details, secrets, keys, real card data, or instructions that enable unauthorized access.

Preferred reporting path:

1. Use GitHub's private vulnerability reporting or Security Advisory workflow for this repository, if available.
2. If private reporting is unavailable, open a minimal public issue that says a private security report is needed, without technical exploit details.

Please include:

- Affected commit or release.
- A concise description of the vulnerability.
- Steps to reproduce using synthetic data where possible.
- Impact and affected components.
- Whether the issue also affects upstream Chameleon Ultra.

## Out of Scope

The maintainers will not provide assistance for:

- Unauthorized card emulation or credential cloning.
- Payment, fare, identity, or access-control bypass.
- Requests for keys, protected data, card dumps, or secrets.
- Exploit chains against third-party systems.
- Circumventing law, contracts, terms of service, or technical protection measures.

## Disclosure

Please allow a reasonable time for analysis and remediation before public disclosure. Coordinated disclosure helps protect users and avoids creating unnecessary risk.
