# Starter policy library (plan §20.4): the five example gates the plan itself names. Each is its
# own `deny contains msg if { ... }` block in the same rule name, which Rego unions automatically --
# the shape `core.policy.opa.eval_deny` always queries (`data.<package>.deny`), matching the plan's
# own worked example (§20.4's KEV+reachable rule, reproduced below unchanged).
#
# Fields referenced here come from `core.policy.input.issue_document` -- see that module's own
# docstring for which two (`license`, `triage_expires_at`) are only sometimes present and why.
package gate.pull_request

import rego.v1

# 1. No reachable KEV vulnerability -- the plan's own worked example.
deny contains msg if {
	some issue in input.new_issues
	issue.in_cisa_kev
	issue.reachable
	msg := sprintf("%s is actively exploited (CISA KEV) and reachable from %s", [issue.id, issue.entrypoint])
}

# 2. No secrets, ever, regardless of severity or reachability -- a leaked credential is dangerous
# the moment it exists in history, not only if something in the code happens to use it.
deny contains msg if {
	some issue in input.new_issues
	issue.category == "secrets"
	msg := sprintf("%s is a leaked secret", [issue.id])
}

# 3. No critical issues in new code -- "new" is already what `input.new_issues` means (the caller
# builds it from `core.ci.compare`'s own new-vs-baseline diff), so this rule needs no extra check
# for that.
deny contains msg if {
	some issue in input.new_issues
	issue.severity == "CRITICAL"
	msg := sprintf("%s is a new critical-severity issue", [issue.id])
}

# 4. A license denylist -- illustrative, meant to be replaced with an organization's own list once
# Week 40's SBOM/license work gives `issue.license` a real value; until then this rule is dead code
# in practice (no finding ever carries `license`), not silently wrong.
denied_licenses := {"AGPL-3.0", "GPL-3.0", "SSPL-1.0"}

deny contains msg if {
	some issue in input.new_issues
	issue.license in denied_licenses
	msg := sprintf("%s uses a denylisted license (%s)", [issue.id, issue.license])
}

# 5. Accepted risk may not exceed 90 days -- re-checked on every evaluation, not only when the
# acceptance was granted, so an org that widens its own policy later still catches an
# already-existing acceptance that now exceeds it.
max_accepted_risk_ns := 90 * 24 * 60 * 60 * 1000 * 1000 * 1000

deny contains msg if {
	some issue in input.new_issues
	issue.triage_status == "accepted"
	expires := time.parse_rfc3339_ns(issue.triage_expires_at)
	(expires - time.now_ns()) > max_accepted_risk_ns
	msg := sprintf("%s's accepted risk extends beyond the 90-day limit", [issue.id])
}

# 6. No malicious packages, ever (plan §20.5) -- osv-scanner already flags an OSSF
# malicious-packages report (a MAL- id) as `malicious: true`; unlike a graded vulnerability this is
# not a matter of severity or reachability, the same reasoning as rule 2's secrets.
deny contains msg if {
	some issue in input.new_issues
	issue.malicious
	msg := sprintf("%s is a reported malicious package", [issue.id])
}
