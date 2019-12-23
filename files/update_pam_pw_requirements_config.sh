#!/bin/bash

CP=$(authselect current | awk 'NR == 1 {print $3}' | grep custom/) 

for FN in system-auth password-auth; do

  [[ -n $CP ]] && PTF=/etc/authselect/$CP/$FN || PTF=/etc/authselect/$FN
  [[ -z $(grep -E '^\s*password\s+requisite\s+pam_pwquality.so\s+.*enforce-for-root\s*.*$' $PTF) ]] && sed -ri 's/^\s*(password\s+requisite\s+pam_pwquality.so\s+)(.*)$/\1\2 enforce-for-root/' $PTF
  [[ -n $(grep -E '^\s*password\s+requisite\s+pam_pwquality.so\s+.*\s+retry=\S+\s*.*$' $PTF) ]] && sed -ri '/pwquality/s/retry=\S+/retry=3/' $PTF || sed -ri 's/^\s*(password\s+requisite\s+pam_pwquality.so\s+)(.*)$/\1\2 retry=3/' $PTF 

done

authselect apply-changes

exit 0
