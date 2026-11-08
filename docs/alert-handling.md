# Alert handling

How an alert moves from detection to close-out in SIEMstress, and where each part of
the workflow comes from.

## Lifecycle

```
open ──acknowledge──▶ acknowledged ──resolve──▶ resolved
  ▲                                               │
  └────────────────────reopen (with reason)───────┘
```

| State | Meaning |
|---|---|
| **open** ● | Raised by a rule; nobody has looked yet. |
| **acknowledged** ◐ | Someone has picked it up and is investigating. Acknowledging an unowned alert makes you its assignee. |
| **resolved** ✓ | Closed with a disposition, the actions taken and a summary. |

Resolving an open alert directly acknowledges it at the same moment. Reopening clears
the disposition, actions and summary; the previous close-out stays in the activity log.

These map onto the *Detection & Analysis* → *Containment, Eradication & Recovery* →
*Post-Incident Activity* phases of the NIST SP 800-61 incident-handling lifecycle, at
the scale of a single alert.

## Closing an alert

All three are required:

1. **Disposition**, the analyst's verdict. The categories are the ones common to SOC
   tooling (e.g. Microsoft Sentinel's incident classification):

   | Code | Label | Use when |
   |---|---|---|
   | `true-positive` | True positive | Malicious or unauthorized activity, confirmed. |
   | `benign-positive` | Benign positive | It happened, but it was expected or authorized (admin work, a test). |
   | `false-positive` | False positive | It didn't happen as described: a rule or parsing mistake. |
   | `undetermined` | Undetermined | Not enough information to decide. |

2. **Actions taken**, one or more:

   | Code | Label | NIST phase |
   |---|---|---|
   | `none` | No action needed | — |
   | `blocked-source` | Blocked the source | Containment |
   | `disabled-account` | Disabled the account | Containment |
   | `isolated-host` | Isolated the host | Containment |
   | `reset-credentials` | Reset credentials | Eradication |
   | `removed-access` | Removed access | Eradication |
   | `removed-persistence` | Removed persistence | Eradication |
   | `hardened` | Patched or hardened | Eradication / recovery |
   | `recovered` | Recovered | Recovery |
   | `tuned-rule` | Tuned the rule | Post-incident (lessons learned) |
   | `escalated` | Escalated | Handoff |
   | `other` | Other | Described in the summary |

3. **Summary**: what happened, how you know, and what was done (10+ characters).

Consistency checks: "No action needed" can't be combined with other actions, and a
true positive can't be closed with no action. Every interface (desktop app, terminal
app, CLI) enforces the same rules from `src/siemstress/triage.py`.

## The case record

Each alert carries its evidence (the triggering event's normalized fields and message),
its ATT&CK technique IDs, an assignee, timestamps for raised / acknowledged / resolved,
and an **append-only activity log**: every acknowledgement, assignment, note, resolution
and reopening, with author and time, written in the same transaction as the change.
There is no way to edit or delete log entries from SIEMstress.

**Related events** are the events on the same host within 30 minutes either side of
the alert that share its source address or users, as a starting point for
investigation.

`siemstress case ID` prints the full record as Markdown, ready to attach to a ticket or
report.

## Metrics

`siemstress report --since 30d` summarizes alert handling:

- **MTTA / MTTR**: median time from an alert being raised to acknowledged, and to
  resolved. Medians rather than means, so one forgotten alert doesn't dominate.
- **Disposition breakdown**: how alerts were classified.
- **Per-rule counts and false positives**: rules closed as false positive at least half
  the time (over 3+ alerts) are listed as tuning candidates.
- **Oldest unresolved alert**, to catch the backlog.

## References

- NIST SP 800-61, *Computer Security Incident Handling Guide* (Rev. 2 lifecycle; Rev. 3
  relates it to the NIST Cybersecurity Framework 2.0).
- MITRE ATT&CK, <https://attack.mitre.org/>, for technique IDs on rules and alerts.
- Microsoft Sentinel, *Close incidents / classification* documentation, for the
  disposition categories.
