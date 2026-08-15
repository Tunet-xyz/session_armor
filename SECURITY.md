# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| < 0.3   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in SessionArmor, please report it responsibly.

### How to Report

**Please DO NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email security concerns to: **alex@tunet.xyz**

Include the following in your report:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgement:** Within 48 hours
- **Initial assessment:** Within 5 business days
- **Fix release:** Within 30 days for critical issues

### Scope

The following are in scope:
- Session fixation or hijacking bypasses
- Fingerprint binding bypasses
- Log injection via sanitization bypass
- X-Forwarded-For spoofing past proxy depth controls
- Any bypass of gate middleware security checks

### Out of Scope

- Vulnerabilities in Django itself (report to Django security team)
- Issues requiring physical access to the server
- Social engineering attacks
