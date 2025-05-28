package osv_scan

default allow = false

allow if {
    count(input.results) == 0
}

deny if {
    count(input.results) > 0
}

violation[msg] if {
    # TODO: Needs finer grained checks to determine if the vulnerability is critical or high
    # TODO: Needs to count the number of critical and high vulnerabilities
    # TODO: Needs to check if the vulnerability is in the allowlist
    count(input.results) > 0
    msg := sprintf("Vulnerabilities detected: %d result(s) found", [count(input.results)])
}
