# Security Policy

## Reporting a Vulnerability

If you believe you have found a security vulnerability in this project, please **do not** open a public GitHub issue.

Preferred reporting channels:

- GitHub: use **Security Advisories** ("Report a vulnerability") on the repository, or
- Email: contact the maintainer(me) directly debasisbiswas.dev@proton.me.

When reporting, please include:

- A clear description of the issue and potential impact
- Steps to reproduce (proof-of-concept if possible)
- Affected package(s), versions, and environment details
- Any relevant logs (redact secrets)

## PGP (for sensitive details)

If you want to share sensitive details encrypted, you can use my public PGP key.

Fingerprint:

`B521 D109 5C63 E077 EAE8 54E9 6805 708F 78A1 9272`

Import command:

```bash
# import the public key
curl -s "https://keys.openpgp.org/vks/v1/by-fingerprint/B521D1095C63E077EAE854E96805708F78A19272" | gpg --import
```

(Optional) Verify it after import:

```bash
gpg --fingerprint B521D1095C63E077EAE854E96805708F78A19272
```

## Supported Versions

This project follows semantic versioning.

- Security fixes are provided for the latest published version.

## Response Targets

Best-effort targets (not guaranteed):

- Initial response: within 7 days
- Fix / mitigation guidance: as soon as reasonably possible
