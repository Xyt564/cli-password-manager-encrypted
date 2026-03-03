# 🔐 Security Policy

Thank you for helping improve the security of this project.

This document outlines how to responsibly report vulnerabilities in **PWMGR (CLI Password Manager — Encrypted)**.

---

## 🛡 Supported Versions

Only the latest version on the `main` branch is currently supported with security updates.

Older versions may not receive patches.

---

## 📢 Reporting a Vulnerability

If you discover a security vulnerability, **do not open a public issue**.

Instead, please report it privately:

* Open a **GitHub Security Advisory**

  * Go to:
    `Security` → `Report a vulnerability`
* Or email the maintainer directly (if an email is listed in the repository)

Please include:

* A detailed description of the issue
* Steps to reproduce
* Proof-of-concept (if applicable)
* Impact assessment
* Suggested mitigation (if known)

You will receive a response within **72 hours**.

---

## 🔒 Disclosure Policy

* Vulnerabilities will be acknowledged within 72 hours.
* A fix will be developed and tested as quickly as possible.
* Coordinated disclosure is preferred.
* Credit will be given unless anonymity is requested.

Please allow reasonable time for a patch before public disclosure.

---

## 🧠 Security Design Overview

PWMGR is designed with the following protections:

### Cryptography

* **Key Derivation:** Argon2id

  * Time cost: 3
  * Memory cost: 64MB
  * Parallelism: 4
* **Encryption:** AES-256-GCM (authenticated encryption)
* **Authentication:** 16-byte GCM tag
* **Header Integrity:** Header bound via AAD

### Memory Protection

* `mlock` used to prevent swapping sensitive memory
* Explicit zeroization of:

  * Master passwords
  * Derived keys
  * Plaintext vault buffers
  * Generated passwords

### Brute-Force Mitigation

* Exponential backoff on failed unlock attempts
* Max delay: 30 seconds
* Failed attempt counter stored locally

### Vault Format Protections

* Binary format
* Length-prefixed fields
* Maximum size enforcement
* Entry count limits
* Ciphertext size validation

---

## ⚠️ Threat Model

PWMGR protects against:

* Offline brute-force attacks
* GPU/ASIC password cracking (Argon2id memory hardness)
* Vault file tampering
* Basic memory scraping post-use
* Header manipulation attacks

PWMGR does **not** protect against:

* Malware on the host system
* Root/system compromise
* Keyloggers
* Clipboard interception
* Physical attacks while unlocked

Security depends on the integrity of the host system.

---

## 🧪 Security Best Practices for Users

* Use a strong master password (12+ characters recommended)
* Keep your system patched
* Avoid running as root unnecessarily
* Do not export plaintext vaults on shared systems
* Lock the shell when stepping away

---

## 📦 Dependencies

This project depends on:

* OpenSSL
* Argon2

Security of these libraries is critical to overall project security.

Keep them updated.

---

## 🤝 Responsible Disclosure Commitment

The maintainer is committed to:

* Taking all security reports seriously
* Fixing validated issues promptly
* Being transparent about security improvements

---

Thank you for contributing to the security of this project.

---
