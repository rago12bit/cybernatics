# `opa test core/policy/starter` (plan §20.4: "opa test runs the policy tests in CI") -- one
# positive and one negative case per starter rule, so a future edit to gate.rego that breaks a rule
# (loosens it, or makes it fire on the wrong field) is caught here before it reaches a real PR gate.
package gate.pull_request_test

import data.gate.pull_request.deny
import rego.v1

# 1. KEV + reachable
test_kev_reachable_is_denied if {
	result := deny with input as {"new_issues": [{"id": "A", "in_cisa_kev": true, "reachable": true, "entrypoint": "POST /login"}]}
	count(result) == 1
}

test_kev_but_not_reachable_is_allowed if {
	result := deny with input as {"new_issues": [{"id": "A", "in_cisa_kev": true, "reachable": false}]}
	count(result) == 0
}

# 2. Secrets
test_a_secret_is_denied if {
	result := deny with input as {"new_issues": [{"id": "A", "category": "secrets"}]}
	count(result) == 1
}

test_a_non_secret_sast_finding_is_allowed if {
	result := deny with input as {"new_issues": [{"id": "A", "category": "sast", "severity": "LOW"}]}
	count(result) == 0
}

# 3. Critical severity
test_critical_severity_is_denied if {
	result := deny with input as {"new_issues": [{"id": "A", "severity": "CRITICAL"}]}
	count(result) == 1
}

test_high_severity_is_allowed if {
	result := deny with input as {"new_issues": [{"id": "A", "severity": "HIGH"}]}
	count(result) == 0
}

# 4. License denylist
test_a_denylisted_license_is_denied if {
	result := deny with input as {"new_issues": [{"id": "A", "license": "GPL-3.0"}]}
	count(result) == 1
}

test_a_permissive_license_is_allowed if {
	result := deny with input as {"new_issues": [{"id": "A", "license": "MIT"}]}
	count(result) == 0
}

test_no_license_data_at_all_is_allowed if {
	# The realistic case today (Week 40 hasn't landed license data yet): the field is simply
	# absent, not `null` or `"unknown"` -- must not be treated as a match.
	result := deny with input as {"new_issues": [{"id": "A"}]}
	count(result) == 0
}

# 5. Accepted risk beyond 90 days
test_an_acceptance_expiring_far_in_the_future_is_denied if {
	result := deny with input as {"new_issues": [{"id": "A", "triage_status": "accepted", "triage_expires_at": "2030-01-01T00:00:00Z"}]}
	count(result) == 1
}

test_an_acceptance_expiring_within_90_days_is_allowed if {
	soon := time.format(time.now_ns() + (10 * 24 * 60 * 60 * 1000 * 1000 * 1000))
	result := deny with input as {"new_issues": [{"id": "A", "triage_status": "accepted", "triage_expires_at": soon}]}
	count(result) == 0
}

test_an_open_untriaged_issue_is_never_checked_against_the_90_day_rule if {
	result := deny with input as {"new_issues": [{"id": "A"}]}
	count(result) == 0
}

# 6. Malicious packages
test_a_malicious_package_is_denied if {
	result := deny with input as {"new_issues": [{"id": "A", "malicious": true}]}
	count(result) == 1
}

test_a_non_malicious_package_is_allowed if {
	result := deny with input as {"new_issues": [{"id": "A", "malicious": false}]}
	count(result) == 0
}

# A benign finding must never trip any rule at once.
test_a_clean_low_severity_finding_is_allowed if {
	result := deny with input as {"new_issues": [{"id": "A", "severity": "LOW", "category": "sast", "in_cisa_kev": false, "reachable": false, "malicious": false}]}
	count(result) == 0
}
