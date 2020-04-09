#!/bin/bash

PTF=$1
DENY=$2
TIME=$3

[[ -n $(grep -E '^\s*auth\s+required\s+pam_faillock.so\s+.*deny=\S+\s*.*$' $PTF) ]] && sed -ri "/pam_faillock.so/s/deny=\S+/deny=${DENY}/g" $PTF || sed -ri "s/^\s*(auth\s+required\s+pam_faillock\.so\s+)(.*[^{}])(\{.*\}|)$/\1\2 deny=${DENY} \3/" $PTF
[[ -n $(grep -E '^\s*auth\s+required\s+pam_faillock.so\s+.*unlock_time=\S+\s*.*$' $PTF) ]] && sed -ri "/pam_faillock.so/s/unlock_time=\S+/unlock_time=${TIME}/g" $PTF || sed -ri "s/^\s*(auth\s+required\s+pam_faillock\.so\s+)(.*[^{}])(\{.*\}|)$/\1\2 unlock_time=${TIME} \3/" $PTF

authselect apply-changes

exit 0
