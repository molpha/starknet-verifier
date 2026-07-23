# Security Policy

## Status

The Molpha Starknet Verifier is currently a **testnet implementation** developed for the Brebeneskul release.

The contracts have **not** completed an independent security audit and should not be used to secure production assets.

---

# Reporting a vulnerability

Please report security issues privately.

**Email**

security@molpha.io

If email is unavailable, contact the team through the official Molpha repository or website.

Please do **not** disclose vulnerabilities publicly before they have been investigated.

---

# What to include

A good report should include:

- description of the issue
- affected contract(s)
- reproduction steps
- proof of concept (preferred)
- impact assessment
- suggested mitigation (optional)

---

# Response process

We aim to:

- acknowledge reports within 3 business days
- investigate and validate the issue
- develop and test a fix
- coordinate responsible disclosure
- credit reporters when appropriate

---

# Supported versions

| Version | Supported |
|---------|-----------|
| Brebeneskul Testnet | ✅ |
| Older commits | ❌ |

---

# Scope

Examples include (but are not limited to):

- signature verification bypass
- Proof-of-Possession bypass
- malformed payload acceptance
- registry corruption
- aggregate public key manipulation
- replay attacks
- denial-of-service vectors
- cryptographic implementation issues
- integer overflows
- authorization bugs

General code quality issues and feature requests should be submitted as GitHub issues instead.

---

# Out of scope

The following are generally out of scope:

- issues in third-party dependencies
- vulnerabilities requiring compromised node keys
- denial-of-service against public RPC providers
- social engineering
- spam
- test-only code
- documentation mistakes

---

# Cryptography

Please include references to relevant papers or standards whenever reporting cryptographic issues.

The verifier is based on:

- BIP-340 Schnorr signatures
- MuSig2-compatible aggregate key construction
- Starknet elliptic curve primitives

---

# Disclosure

Please allow us reasonable time to investigate and deploy fixes before publicly disclosing any vulnerability.

Coordinated disclosure helps protect developers and users integrating the protocol.