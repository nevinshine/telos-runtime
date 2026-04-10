# Security Policy

## Supported Versions

The following versions of Telos Runtime receive security fixes:

| Version / Branch | Supported          |
| ---------------- | ------------------ |
| `main`           | ✅ Yes (current)   |
| Older branches   | ❌ No              |

Only the latest code on the `main` branch is actively maintained. We strongly
recommend always running the most recent version.

---

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

To report a vulnerability privately, use one of the following channels:

- **GitHub Private Security Advisories** (preferred):  
  Navigate to **Security → Report a vulnerability** on this repository and
  submit a draft advisory. This keeps the disclosure confidential until a fix
  is ready.
- **Email**: If you cannot use GitHub advisories, email the maintainer at
  the address listed in the repository's GitHub profile. Use the subject line
  `[SECURITY] telos-runtime — <short description>`.

Please include in your report:
- A clear description of the vulnerability and its potential impact.
- Steps to reproduce or a proof-of-concept (PoC) if available.
- The affected component(s) (eBPF loader, Python cortex, gRPC interface, etc.).
- Any suggested mitigations or patches you may have.

---

## Response & Triage Timeline

| Activity                           | Target SLA                  |
| ---------------------------------- | -------------------------   |
| Acknowledgement of report          | ≤ 72 hours                  |
| Initial triage / severity decision | ≤ 7 days                    |
| Fix for Critical / High severity   | ≤ 30 days                   |
| Fix for Medium severity            | ≤ 60 days                   |
| Fix for Low / Informational        | Next regular release cycle  |

We will keep reporters updated on progress and may request additional
information during investigation.

---

## Coordinated Disclosure Process

1. Reporter submits a private report through one of the channels above.
2. Maintainers acknowledge receipt and begin triage.
3. An embargo period is agreed upon (typically 30–90 days, depending on
   severity and complexity of the fix).
4. A patch is developed, reviewed, and tested privately.
5. A new release / patch commit is published on `main`.
6. A public security advisory is published on GitHub simultaneously with
   the fix, crediting the reporter (unless they prefer to remain anonymous).
7. Where applicable, a CVE is requested through GitHub's CVE numbering
   authority.

---

## Scope

### In Scope
- eBPF LSM loader and BPF programs (`telos_core/`, `telos_edge/`)
- Python Cortex decision engine (`cortex/`)
- gRPC interface and protocol definitions (`shared/`)
- Privilege escalation or sandbox-escape paths in any component
- Supply-chain issues (dependency confusion, malicious transitive deps)
- Secrets or credentials inadvertently committed to the repository

### Out of Scope
- Vulnerabilities in third-party dependencies already tracked upstream
  (report those to the respective project; link the advisory in your report
  so we can track the upgrade)
- Issues in the `deploy/vulnerable_agent/` red-team simulation scripts
  (these are intentionally insecure for testing purposes)
- Security concerns in environments that deviate from the documented
  deployment configuration
- Denial-of-service attacks that require physical or root-level access to
  the host machine

---

## Attribution

We sincerely thank security researchers who responsibly disclose
vulnerabilities. With your permission, we will credit you in the associated
GitHub security advisory and release notes.
