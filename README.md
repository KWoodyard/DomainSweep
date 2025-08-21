# DomainSweep

**DomainSweep** is a safe, read-only Active Directory hygiene audit tool designed for penetration testers and security professionals. It performs a variety of checks on an AD environment, outputs color-coded tables to the console, and optionally logs results to a file.

---

## Features

- ✅ Fully **console-based**, no CSV files required  
- ✅ Optional **output file** via `> output.txt`  
- ✅ **Color-coded severity**: Info = white, Warning = yellow, Critical = red  
- ✅ ASCII banner on startup  
- ✅ Checks include:
  - Account hygiene (stale accounts, password policies)
  - Kerberos risks (ASREP, weak SPNs)
  - Delegation issues (unconstrained / any protocol)
  - Shadow admins / risky ACLs
  - SYSVOL writable scripts
  - LAPS coverage  
- ✅ Safe, read-only **AD audit**

---
