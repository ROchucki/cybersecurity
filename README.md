# Cybersecurity

Learning repository for cybersecurity: modules, notes, reports, and OSINT documentation.

Everything here is studied and practiced **in legal lab environments only** (TryHackMe, HackTheBox, own virtual machines such as Metasploitable/DVWA).

## Structure

```
cybersecurity/
├── security/
│   ├── modules/         # Learning modules: one topic/tool per file (e.g. nmap.md)
│   ├── reports/
│   │   ├── examples/    # Sanitized example reports from labs
│   │   └── private/     # Personal lab notes (kept anonymized)
│   └── shared/          # Cross-topic resources (glossaries, checklists)
├── osint/
│   └── notes/           # OSINT techniques and case notes
├── docs/                # General documentation and references
└── README.md
```

## Modules

| Module | Topic | Status |
|---|---|---|
| [nmap.md](security/modules/nmap.md) | Network scanning & discovery | In progress |

## Conventions

- Language: **English** for all content (commits, docs, notes).
- Commit style: imperative, short — `Add Nmap cheatsheet module`.
- One tool/topic = one module file in `security/modules/`.
- Every module follows the same template: purpose → how it works → commands by task → lab notes → legal notes.

## Safety & legality rules

- Scan **only** machines you own or lab environments with explicit permission.
- Never commit real scan results against third-party systems, real IPs, or credentials.
- Anonymize lab IPs if they resemble production networks.
- Unauthorized scanning is illegal in most jurisdictions (in Poland: art. 267 KK).
