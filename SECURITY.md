# 🛡️ Security Policy & Compliance Guidelines

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.5.x   | :white_check_mark: |
| 2.0.x   | :x:                |
| < 2.0   | :x:                |

## Reporting a Vulnerability

The **NEXAVOR QUANTUM AUDIT** platform and **RustShield** take security vulnerabilities seriously. We appreciate your efforts to responsibly disclose your findings.

### Reporting Process
1. **Do not create public GitHub issues** for security-sensitive bugs or zero-days.
2. Email your findings directly to the security team or use private vulnerability reporting on GitHub.
3. Include detailed steps to reproduce the issue, proof-of-concept (PoC), and potential impact.

### Security Guarantees & Red Team Standards
- **Zero OS Command Injection**: All Git and CLI interactions use safe system calls via `execve` without intermediate shell wrappers.
- **Post-Quantum Cryptographic Compliance**: Algorithms aligned with ML-KEM and quantum-resistant standards.
- **Automated BPMN DevSecOps**: Continuous vulnerability scanning and autonomous patch submission.
