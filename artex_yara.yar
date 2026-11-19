/*
 * ARTEX AI Autonomous Penetration Testing Framework - Detection Rules
 * Target: BaaRai/ARTEX and copy-cat forks / derivatives
 * Purpose: Defensive detection for IDS/IPS, SIEM, EDR, file scanning
 * Version: 2026-11-19
 * Confidence: High when multiple strings match; medium for single strong indicators
 *
 * Notes:
 * - These target code-derived artifacts that survive rebranding of UI text.
 * - Prefer multi-string rules to reduce false positives.
 * - Network rules (Suricata) are in the companion file.
 * - Update hashes if major UI assets change in future releases.
 */

rule ARTEX_Binary_Core_Strings
{
    meta:
        description = "Detects ARTEX Go binary via unique internal strings"
        author = "Defensive detection pack"
        date = "2026-11-19"
        reference = "https://github.com/BaaRai/ARTEX"
        severity = "high"
        tlp = "white"

    strings:
        $s1 = "artex-pace" ascii wide
        $s2 = "artex-traffic-trace" ascii wide
        $s3 = "artex-update-check" ascii wide
        $s4 = "ARTEX_TARGET_USER_AGENT" ascii wide
        $s5 = "ARTEX_NOISE_PROFILE" ascii wide
        $s6 = "exploration_nodes" ascii wide
        $s7 = "artex-data-marker-removed" ascii wide
        $s8 = "github.com/Autumn-27/artex" ascii wide
        $s9 = "github.com/Autumn-27/norma" ascii wide
        $s10 = "artex-skills-" ascii wide

    condition:
        uint16(0) == 0x457f and  // ELF
        4 of them
}

rule ARTEX_Binary_Env_And_Config
{
    meta:
        description = "ARTEX environment variables and config markers"
        severity = "high"

    strings:
        $e1 = "ARTEX_PG_DSN" ascii
        $e2 = "ARTEX_SECRET_KEY" ascii
        $e3 = "ARTEX_BIND_ADDR" ascii
        $e4 = "ARTEX_TRUSTED_PROXIES" ascii
        $e5 = "noise_profile" ascii
        $e6 = "jwt.key" ascii
        $e7 = "auth.password_hash" ascii

    condition:
        3 of them
}

rule ARTEX_UI_Title_And_Login
{
    meta:
        description = "ARTEX web console title and hardcoded login username"
        severity = "medium"

    strings:
        $title1 = "ARTEX — Autonomous Penetration Testing Console" ascii wide
        $title2 = "Autonomous Penetration Testing Console" ascii wide
        $login = "login(\"ARTEX\"" ascii
        $user = "value=\"ARTEX\"" ascii
        $brand = "name: \"ARTEX\"" ascii

    condition:
        any of them
}

rule ARTEX_Proxy_Credentials
{
    meta:
        description = "ARTEX recording proxy default credentials (artex-pace)"
        severity = "high"

    strings:
        $pace = "artex-pace:artex-pace" ascii
        $ua_pace = "artex-pace" ascii
        $proxy = "8788" ascii
        $trace = "artex-traffic-trace" ascii

    condition:
        2 of them
}

rule ARTEX_Database_Schema
{
    meta:
        description = "ARTEX PostgreSQL schema identifiers"
        severity = "medium"

    strings:
        $t1 = "exploration_nodes" ascii
        $t2 = "exploration_edges" ascii
        $t3 = "exploration_anchors" ascii
        $t4 = "ck_node_kind" ascii
        $t5 = "ck_node_state" ascii

    condition:
        3 of them
}

rule ARTEX_Favicon_SHA256
{
    meta:
        description = "Known ARTEX default favicon (SHA-256)"
        hash_sha256 = "8b567c0244f2dbee787165aea9c4ddabaaafb0fdb3b29899ac898c60a589856b"
        severity = "medium"

    condition:
        hash.sha256(0, filesize) == "8b567c0244f2dbee787165aea9c4ddabaaafb0fdb3b29899ac898c60a589856b"
}
