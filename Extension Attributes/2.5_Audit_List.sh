#!/bin/bash

# Security Reporting - List Risks

auditfile=/Library/Application\ Support/SecurityScoring/org_audit
echo "<result>$(cat "$auditfile")</result>"