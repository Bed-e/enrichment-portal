# Verdict rules, proposed `rules_version` 0.1

Status: **approved for implementation** (all four review questions decided, see "Decisions").

Originally proposed for review (design.md D7). The verdict engine is not written until you approve this file. Changes you ask for are made here first.

The verdict is a pure function of the classification and the list of source results. It uses no scoring arithmetic: every rule is a plain condition, so any verdict can be explained by reading its `reasons`.

## What the three M1 sources can tell us

| Source | Kind | Can it raise a red flag? |
|---|---|---|
| Shodan InternetDB | Exposure and tags | **Yes**, through `tags` and `vulns` |
| RDAP | Registration and ownership | No |
| Team Cymru | ASN and BGP prefix | No |

Only InternetDB can produce a signal. RDAP and Team Cymru describe *who owns* an address, which says nothing about whether it is malicious, so in 0.1 they produce no signals. They still count as "answered" for the coverage rules below. Reputation sources arrive in M2, which bumps `rules_version`.

**Caveat on tags.** Shodan documents InternetDB's response fields but not the tag values (checked 11/5/26, design.md section 4). The names below come from third-party lists and Shodan's blog, so they are unconfirmed and may change. Tags are compared case-insensitively. Any tag not listed here (for example `cloud`, `cdn`, `pqc`) is ignored and does not appear in `reasons`.

## Signals

Each signal that fires becomes one entry in `verdict.reasons` as `{source, signal, weight}`.

| # | Condition (InternetDB `ok` only) | `signal` text | Weight | Why |
|---|---|---|---|---|
| S1 | tag `c2`, `malware`, `compromised` or `doublepulsar` | `Shodan tag: <tag>` | high | These describe the host as attacker infrastructure or as infected. |
| S2 | tag `tor`, `onion`, `vpn` or `proxy` | `Shodan tag: <tag>` | medium | Anonymising infrastructure. Often legitimate, but attackers use it to hide, and an analyst should look closer. |
| S3 | `vulns` has one or more CVEs | `Exposed to N known CVE(s)` | low | Describes the host's exposure, not its intent. A vulnerable host may be a victim. |
| S4 | tag `honeypot` | `Shodan tag: honeypot` | low | The host is probably *bait*, not an attacker. Shown for context, never raises the level. |

One signal is listed per matching tag, so an IP tagged both `tor` and `vpn` has two medium reasons.

## Levels

Rules are applied top to bottom. The first that matches decides the level.

| # | Condition | Level |
|---|---|---|
| L1 | The IP is private or reserved (`classification.is_global` is false) | `not_applicable` |
| L2 | No source ended in `ok` or `no_data` | `unknown` |
| L3 | InternetDB did not end in `ok` or `no_data` | `unknown` |
| L4 | At least one **high** signal | `malicious` |
| L5 | At least one **medium** signal | `suspicious` |
| L6 | Otherwise | `no_known_bad` |

- Low signals never change the level. They only appear in `reasons`.
- Several medium signals stay `suspicious`. Several of any weight never add up to a higher level.
- The app never says "clean" (D8).

## Summary text

`verdict.summary` is built from the level, plus a coverage note:

| Level | Summary |
|---|---|
| `not_applicable` | "<Category> address. External sources were not queried." (as in M0) |
| `unknown` (L2) | "No source could answer, so nothing can be said about this IP." (as in M0) |
| `unknown` (L3) | "Shodan InternetDB, the only source that can flag an IP, did not answer, so nothing can be said about this IP." |
| `malicious` | "Flagged by: <the high signals>." |
| `suspicious` | "Worth a closer look: <the medium signals>." |
| `no_known_bad` | "No red flags found. Only context sources were checked, not reputation sources, so this is weak evidence." |

After the summary of any global-IP verdict except L2 (where every source failed), if some sources did not answer, add one sentence naming them, for example "Not answered: RDAP (timeout)." `timeout`, `error`, `rate_limited` and `not_configured` all count as missing evidence and never make a verdict look cleaner.

## Examples

| InternetDB | RDAP | Cymru | Level | Reasons |
|---|---|---|---|---|
| `ok`, tags `[]`, no CVEs | `ok` | `ok` | `no_known_bad` | none |
| `ok`, tags `[c2]` | `ok` | `ok` | `malicious` | InternetDB: `Shodan tag: c2` (high) |
| `ok`, tags `[tor]` | `no_data` | `ok` | `suspicious` | InternetDB: `Shodan tag: tor` (medium) |
| `ok`, tags `[]`, 3 CVEs | `ok` | `ok` | `no_known_bad` | InternetDB: `Exposed to 3 known CVE(s)` (low) |
| `ok`, tags `[honeypot]` | `ok` | `ok` | `no_known_bad` | InternetDB: `Shodan tag: honeypot` (low) |
| `no_data` | `ok` | `ok` | `no_known_bad` | none |
| `timeout` | `ok` | `ok` | `unknown` (L3) | none |
| `timeout` | `timeout` | `error` | `unknown` (L2) | none |
| any | any | any, IP is `10.0.0.5` | `not_applicable` | none |

## Decisions

1. **L3 stays, as `unknown`** (decided). "No red flags" only means something if a source that can raise a flag looked. RDAP and Team Cymru cannot, so their answers alone never produce `no_known_bad`. Recorded in design.md D6 and the section 3 field rules.
2. **Tag lists and weights S1 to S4** (confirmed as written).
3. **Exposed CVEs stay low** (decided). They describe how exposed a host is, not whether it is a threat, and a heavily vulnerable host is often a victim. InternetDB also matches CVEs from banner versions, which can be false positives. Revisit when a reputation source can corroborate.
4. **Several medium signals stay `suspicious`** (decided). The medium tags are strongly correlated rather than independent evidence. One commercial VPN exit commonly carries `vpn` and `proxy` together, and a Tor relay carries `tor` and `onion`. Counting each tag separately would escalate benign anonymising services to `malicious`.
