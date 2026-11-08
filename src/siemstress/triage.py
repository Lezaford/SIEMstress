# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Alert triage vocabulary and the rules for closing an alert.

Dispositions follow the classification common to SOC tooling (e.g. Microsoft
Sentinel); actions follow the containment, eradication and recovery phases of
NIST SP 800-61 incident handling.
"""

from dataclasses import dataclass


class TriageError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Choice:
    code: str
    label: str
    help: str


TRUE_POSITIVE = "true-positive"
BENIGN_POSITIVE = "benign-positive"
FALSE_POSITIVE = "false-positive"
UNDETERMINED = "undetermined"

DISPOSITIONS = {
    c.code: c
    for c in (
        Choice(TRUE_POSITIVE, "True positive", "Malicious or unauthorized activity, confirmed."),
        Choice(BENIGN_POSITIVE, "Benign positive",
               "The activity happened but was expected or authorized, e.g. admin work or a test."),
        Choice(FALSE_POSITIVE, "False positive",
               "The activity didn't happen as the alert says: a rule or parsing mistake."),
        Choice(UNDETERMINED, "Undetermined", "Not enough information to decide."),
    )
}  # fmt: skip

NO_ACTION = "none"
ACTIONS = {
    c.code: c
    for c in (
        Choice(NO_ACTION, "No action needed", "Nothing to contain or fix."),
        Choice("blocked-source", "Blocked the source", "Firewall or network block on the origin."),
        Choice("disabled-account", "Disabled the account", "Locked or disabled a user account."),
        Choice("reset-credentials", "Reset credentials", "Changed passwords, keys or tokens."),
        Choice("removed-access", "Removed access", "Took away privileges or group membership."),
        Choice("removed-persistence", "Removed persistence",
               "Deleted an unauthorized account, key, job or service."),
        Choice("isolated-host", "Isolated the host", "Cut the machine off from the network."),
        Choice("hardened", "Patched or hardened", "Updated or reconfigured to close the hole."),
        Choice("recovered", "Recovered", "Restored data or service to normal."),
        Choice("tuned-rule", "Tuned the rule", "Adjusted or suppressed the detection."),
        Choice("escalated", "Escalated", "Handed to someone else to act on."),
        Choice("other", "Other", "Something else, described in the summary."),
    )
}  # fmt: skip

MIN_SUMMARY = 10


def check_resolution(disposition: str, actions: list[str], summary: str) -> None:
    """Raise TriageError unless this is a complete, consistent close-out."""
    if disposition not in DISPOSITIONS:
        raise TriageError(f"choose a disposition: {', '.join(DISPOSITIONS)}")
    if unknown := [a for a in actions if a not in ACTIONS]:
        raise TriageError(f"unknown actions {unknown}; choose from {', '.join(ACTIONS)}")
    if not actions:
        raise TriageError(f"record the actions taken, or '{ACTIONS[NO_ACTION].label}'")
    if NO_ACTION in actions and len(actions) > 1:
        raise TriageError(f"'{ACTIONS[NO_ACTION].label}' can't be combined with other actions")
    if disposition == TRUE_POSITIVE and actions == [NO_ACTION]:
        raise TriageError("a true positive needs the containment or recovery actions taken")
    if len(summary.strip()) < MIN_SUMMARY:
        raise TriageError(f"write a resolution summary (at least {MIN_SUMMARY} characters)")


def describe(disposition: str | None, actions: tuple[str, ...]) -> str:
    """One line for logs and lists, e.g. 'False positive; actions: Tuned the rule'."""
    if not disposition:
        return ""
    labels = ", ".join(ACTIONS[a].label for a in actions if a in ACTIONS)
    return f"{DISPOSITIONS[disposition].label}; actions: {labels or 'none recorded'}"
