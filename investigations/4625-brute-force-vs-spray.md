# 4625 — Failed Logon Analysis

## Scenario
Reviewed the Security log on a local Windows workstation, filtered to Event ID 4625.
6 events returned across 4 days (2026-09-20 → 2026-09-23).

## Filter
Event Viewer → Windows Logs → Security → Filter Current Log → Event ID: 4625

## Findings
| Field | Observed | Meaning |
|---|---|---|
| Account | local desktop user | valid, existing account |
| Logon Type | 2 | interactive, physical keyboard |
| Sub Status | 0xC000006A | correct user, wrong password |
| Source IP | 127.0.0.1 | loopback — not remote |
| Logon Process | User32 | local authentication |

## Verdict
Benign — user error (mistyped local password). No escalation.

## Why this is NOT an attack
- Type 2 + loopback = not network-based
- 0xC000006A alone = not username enumeration
- Single known account = not password spray

## What a suspicious 4625 would look like
- Logon Type 3 or 10
- External source IP
- Many usernames (spray) or rapid repeats (brute force)
- Mix of 0xC0000064 + 0xC000006A
