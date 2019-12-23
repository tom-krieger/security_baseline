#!/bin/bash

DENY=$1
TIME=$2
CP=$(authselect current | awk 'NR == 1 {print $3}' | grep custom/) 

for FN in system-auth password-auth; do

  [[ -n $CP ]] && PTF=/etc/authselect/$CP/$FN || PTF=/etc/authselect/$FN
  [[ -n $(grep -E '^\s*auth\s+required\s+pam_faillock.so\s+.*deny=\S+\s*.*$' $PTF) ]] && sed - ri "/pam_faillock.so/s/deny=\S+/deny=${DENY}/g" $PTF || sed -ri "s/^\^\s*(auth\s+required\s+pam_faillock\.so\s+)(.*[^{}])(\{.*\}|)$/\1\2 deny=${DENY} \3/" $PTF
  [[ -n $(grep -E '^\s*auth\s+required\s+pam_faillock.so\s+.*unlock_time=\S+\s*.*$' $PTF) ]] && sed -ri "/pam_faillock.so/s/unlock_time=\S+/unlock_time=${TIME}/g" $PTF || sed -ri "s/^\s*(auth\s+required\s+pam_faillock\.so\s+)(.*[^{}])(\{.*\}|)$/\1\2 unlock_time=${TIME} \3/" $PTF

done

authselect apply-changes

exit 0
