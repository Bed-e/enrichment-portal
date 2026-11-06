# Verdict rules

| Version | Status |
|---|---|
| 0.1 | Approved and in force (M1). Keyless sources only. |
| **0.2** | **Approved for implementation** (M2, design.md D7). The four review questions are decided; see "Decisions in 0.2". |

This file describes 0.2. Everything from 0.1 that 0.2 does not change is kept as decided, and the 0.1 decisions are listed at the end.

The verdict is a pure function of the classification and the list of source results. It uses no scoring arithmetic: every rule is a plain condition, so any verdict can be explained by reading its `reasons`.

## What each source can tell us

| Source | Kind | Can it raise a red flag? |
|---|---|---|
| Shodan InternetDB | Exposure and tags | **Yes**, through `tags` and `vulns` |
| AbuseIPDB | Crowd-sourced abuse reports | **Yes**, through the confidence score and Tor flag |
| GreyNoise Community | Internet scanner and benign-service data | **Yes**, through `classification` and `noise` |
| VirusTotal | Vendor detections | **Yes**, through the count of vendors flagging it malicious |
| RDAP | Registration and ownership | No |
| Team Cymru | ASN and BGP prefix | No |
| ipinfo Lite | ASN, country | No |

The first four are the **flagging sources**. The last three describe *who owns or routes* an address, which says nothing about whether it is malicious, so they produce no signals. They still count as "answered" for the coverage note.

## What the recorded responses showed

The 0.2 thresholds were set after looking at real responses for 8.8.8.8 (Google's public DNS, a well-known benign address), recorded 11/5/26:

- **VirusTotal:** 1 of about 92 vendors flags it as malicious (`malicious: 1`, `harmless: 54`, `undetected: 37`), with community reputation +564. A single detection on a benign address is normal.
- **AbuseIPDB:** 198 reports but a confidence score of 0, and `isWhitelisted: true`. Reports alone do not mean abuse.
- **GreyNoise:** HTTP 404 (not seen scanning the internet). On the free tier 8.8.8.8 and 1.1.1.1 both answered 404, so no real "ok" response has been seen.
- **InternetDB:** tags `["pqc"]`, which is not a flag.

An earlier draft of this plan treated 1 to 4 VirusTotal detections as medium. That would have called 8.8.8.8 `suspicious`, so the VirusTotal thresholds below are higher.

## Signals

Each signal that fires becomes one entry in `verdict.reasons` as `{source, signal, weight}`. Signals are read only from a source whose status is `ok`.

### Unchanged from 0.1 (InternetDB)

**Caveat on tags.** Shodan documents InternetDB's response fields but not the tag values (design.md section 4). The names come from third-party lists and Shodan's blog, so they are unconfirmed. Tags are compared case-insensitively, and any tag not listed (for example `cloud`, `cdn`, `pqc`) is ignored.

| # | Condition | `signal` text | Weight |
|---|---|---|---|
| S1 | tag `c2`, `malware`, `compromised` or `doublepulsar` | `Shodan tag: <tag>` | high |
| S2 | tag `tor`, `onion`, `vpn` or `proxy` | `Shodan tag: <tag>` | medium |
| S3 | `vulns` has one or more CVEs | `Exposed to N known CVE(s)` | low |
| S4 | tag `honeypot` | `Shodan tag: honeypot` | low |

### New in 0.2

| # | Source and condition | `signal` text | Weight | Why |
|---|---|---|---|---|
| S5 | **AbuseIPDB** confidence score 75 to 100 | `AbuseIPDB confidence score N/100` | high | Most of the community's reports agree the IP is abusive. |
| S6 | AbuseIPDB confidence score 25 to 74 | `AbuseIPDB confidence score N/100` | medium | Reported, but not conclusively. |
| S7 | AbuseIPDB confidence score 1 to 24 | `AbuseIPDB confidence score N/100` | low | A few reports. |
| S8 | AbuseIPDB `isTor` is true | `AbuseIPDB: Tor exit node` | medium | Same reasoning as S2. |
| S9 | **VirusTotal** 10 or more vendors flag it malicious | `VirusTotal: N vendors flag it as malicious` | high | A broad consensus of detection engines. |
| S10 | VirusTotal 3 to 9 vendors flag it malicious | `VirusTotal: N vendors flag it as malicious` | medium | Several vendors agree, but not a consensus. |
| S11 | VirusTotal 1 or 2 vendors flag it malicious | `VirusTotal: N vendor(s) flag it as malicious` | low | A lone detection is often a false positive: 8.8.8.8 has one. |
| S12 | **GreyNoise** `classification` is `malicious` | `GreyNoise classification: malicious` | high | GreyNoise has judged the traffic it saw as malicious. |
| S13 | GreyNoise `noise` is true and the classification is not `malicious` or `benign` | `GreyNoise: seen scanning the internet` | low | Mass scanners include many harmless researchers. |

A score of 0 (S5 to S7) and a VirusTotal count of 0 produce no signal. Not used in 0.2: VirusTotal `suspicious`, `reputation` and `harmless` counts, AbuseIPDB report counts, and anything from RDAP, Team Cymru and ipinfo.

**Benign information is a note, not a signal.** If AbuseIPDB reports `isWhitelisted`, or GreyNoise reports `riot` or classification `benign`, the summary adds one sentence such as "GreyNoise lists it as a known benign service." It does not change the level, because the verdict never says "clean" (D8) and `reasons` only holds red flags. See question 3.

## Levels

Rules apply top to bottom. The first that matches decides the level.

| # | Condition | Level |
|---|---|---|
| L1 | The IP is private or reserved (`classification.is_global` is false) | `not_applicable` |
| L2 | No source ended in `ok` or `no_data` | `unknown` |
| L3 | **None of the four flagging sources** ended in `ok` or `no_data` | `unknown` |
| L4 | At least one **high** signal | `malicious` |
| L5 | At least one **medium** signal | `suspicious` |
| L6 | Otherwise | `no_known_bad` |

- **L3 is the 0.1 decision, generalised.** In 0.1 InternetDB was the only flagging source, so "InternetDB failed" meant `unknown`. With more flagging sources, the same reasoning (no one who *can* raise a flag looked) gives: `unknown` only when none of the four answered. If InternetDB fails but AbuseIPDB answered, a flagging source did look, so the verdict can be `no_known_bad`.
- A flagging source that returns `no_data` (AbuseIPDB with zero reports, GreyNoise 404, VirusTotal 404) counts as having looked.
- Low signals never change the level. Several medium signals stay `suspicious`, whichever sources they come from (see question 2).
- The app never says "clean" (D8).

## Summary text

| Level | Summary |
|---|---|
| `not_applicable` | "<Category> address. External sources were not queried." (as in 0.1) |
| `unknown` (L2) | "No source could answer, so nothing can be said about this IP." (as in 0.1) |
| `unknown` (L3) | "None of the sources that can flag an IP (<their names>) answered, so nothing can be said about this IP." |
| `malicious` | "Flagged by: <the high signals>." |
| `suspicious` | "Worth a closer look: <the medium signals>." |
| `no_known_bad` | "No red flags found by <the flagging sources that answered, listed by name>." If only InternetDB answered: the 0.1 wording, "No red flags found. Only context sources were checked, not reputation sources, so this is weak evidence." |

`no_known_bad` stops saying "weak evidence" once a reputation source (AbuseIPDB, GreyNoise or VirusTotal) answered, because the evidence is no longer only exposure tags.

After any global-IP summary except L2, if some sources did not answer, one sentence names them with the reason, for example "Not answered: GreyNoise Community (rate limited), ipinfo Lite (not configured)." `timeout`, `error`, `rate_limited` and `not_configured` all count as missing evidence and never make a verdict look cleaner. A rate-limited or unconfigured source is never an error in the verdict.

## Examples

| InternetDB | AbuseIPDB | GreyNoise | VirusTotal | Level | Reasons |
|---|---|---|---|---|---|
| tags `[]` | `no_data` | `no_data` | 0 detections | `no_known_bad` | none |
| tags `[pqc]` | score 0, whitelisted | `no_data` | 1 vendor | `no_known_bad` | VirusTotal: 1 vendor flags it (low). **This is the recorded 8.8.8.8 data.** |
| tags `[]` | score 90 | `no_data` | 0 | `malicious` | AbuseIPDB score 90/100 (high) |
| tags `[]` | score 40 | `no_data` | 5 vendors | `suspicious` | AbuseIPDB 40/100 (medium), VirusTotal 5 vendors (medium) |
| tags `[tor]` | `isTor` | `no_data` | 0 | `suspicious` | Shodan tag: tor (medium), AbuseIPDB: Tor exit node (medium) |
| tags `[]` | `no_data` | classification `malicious` | 0 | `malicious` | GreyNoise classification: malicious (high) |
| tags `[]` | `no_data` | `noise`, unknown | 0 | `no_known_bad` | GreyNoise: seen scanning (low) |
| `timeout` | score 0 | `rate_limited` | 0 | `no_known_bad` | none, and the summary adds "Not answered: Shodan InternetDB (timeout), GreyNoise Community (rate limited)." |
| `timeout` | `timeout` | `rate_limited` | `not_configured` | `unknown` (L3) | none |
| `ok`, no flags | `not_configured` | `not_configured` | `not_configured` | `no_known_bad` | none; the 0.1 "weak evidence" wording. This is a fresh clone with no keys. |

## Decisions in 0.2

1. **VirusTotal thresholds S9 to S11** approved: 10 or more is high, 3 to 9 medium, 1 or 2 low.
2. **Independent sources at medium stay `suspicious`.** Two different reputation sources both at medium do not escalate to `malicious`. This keeps the 0.1 decision simple; revisit if it proves too timid in use.
3. **Known-benign information is a note only.** GreyNoise `riot` or `benign` and AbuseIPDB `isWhitelisted` add a sentence to the summary and never change the level, so they cannot hide a real problem on a compromised service.
4. **AbuseIPDB score bands S5 to S7** approved: 75 to 100 high, 25 to 74 medium, 1 to 24 low.
5. **L3 generalised** (my proposal, accepted with the rest): `unknown` only when none of the four flagging sources answered.

## Decisions already made in 0.1 (still in force)

1. **L3 stays, as `unknown`.** "No red flags" only means something if a source that can raise a flag looked. RDAP and Team Cymru cannot, so their answers alone never produce `no_known_bad`. Recorded in design.md D6 and the section 3 field rules. 0.2 generalises it to "none of the flagging sources answered".
2. **Tag lists and weights S1 to S4** confirmed.
3. **Exposed CVEs stay low.** They describe how exposed a host is, not whether it is a threat, and a heavily vulnerable host is often a victim. InternetDB matches CVEs from banner versions, which can be false positives. Revisit when a reputation source can corroborate.
4. **Several medium signals stay `suspicious`.** The medium tags are strongly correlated rather than independent evidence. One commercial VPN exit commonly carries `vpn` and `proxy` together, and a Tor relay carries `tor` and `onion`. Counting each tag separately would escalate benign anonymising services to `malicious`. 0.2 decision 2 keeps it for independent sources too.
