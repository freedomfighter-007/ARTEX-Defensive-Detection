# ARTEX Defensive Detection Pack

Fingerprints for the ARTEX AI autonomous penetration-testing framework (BaaRai/ARTEX and copy-cats).

## Contents
- `artex_yara.yar` — YARA rules for binary, config, UI, schema, and favicon detection. Suitable for EDR, file scanners, and offline analysis.
- `artex_suricata.rules` — Suricata-style network rules for User-Agents, console titles, ports, and proxy auth. Import into IDS/IPS or SIEM rule engines.

## High-Confidence Indicators
- **Ports**: 8787 (console), 8788 (recording proxy)
- **Favicon SHA-256**: `8b567c0244f2dbee787165aea9c4ddabaaafb0fdb3b29899ac898c60a589856b`
- **UI Title**: "ARTEX — Autonomous Penetration Testing Console"
- **User-Agents**: `artex-update-check`, `artex-pace`, `norma/0.4`, `artex-enrich/*`
- **Proxy credentials**: `artex-pace:artex-pace`
- **DB tables**: `exploration_nodes`, `exploration_edges`, `exploration_anchors`
- **Env / config**: `ARTEX_TARGET_USER_AGENT`, `ARTEX_NOISE_PROFILE`, `ARTEX_PG_DSN`, `jwt.key`

## Usage Notes
- Combine static rules with behavioral detection (machine-speed request bursts, rapid path enumeration).
- Copy-cat forks may change UI titles or default ports; the Go internal strings and schema names are more durable.
- These rules are for authorized defensive use only.
- Test in your environment before deploying as blocking rules.
