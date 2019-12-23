#!/bin/bash

PTF=$1

[[ -z $(grep -E '^\s*password\s+requisite\s+pam_pwquality.so\s+.*enforce-for-root\s*.*$' $PTF) ]] && sed -ri 's/^\s*(password\s+requisite\s+pam_pwquality.so\s+)(.*)$/\1\2 enforce-for-root/' $PTF
[[ -n $(grep -E '^\s*password\s+requisite\s+pam_pwquality.so\s+.*\s+retry=\S+\s*.*$' $PTF) ]] && sed -ri '/pwquality/s/retry=\S+/retry=3/' $PTF || sed -ri 's/^\s*(password\s+requisite\s+pam_pwquality.so\s+)(.*)$/\1\2 retry=3/' $PTF 

authselect apply-changes

exit 0
