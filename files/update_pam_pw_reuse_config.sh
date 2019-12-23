#!/bin/bash

PTF=$1
nr=$2

[[ -n $(grep -E '^\s*password\s+(sufficient\s+pam_unix|requi(red|site)\s+pam_pwhistory).so\s+ ([^#]+\s+)*remember=\S+\s*.*$' $PTF) ]] && sed -ri "s/^\s*(password\s+(requisite|sufficient)\s+(pam_pwquality\.so|pam_unix\.so)\s+)(.*)(remember=\S+\s*)(.*)$/\1\4 remember=${nr} \6/" $PTF || sed -ri "s/^\s*(password\s+(requisite|sufficient)\s+(pam_pwquality\.so|pam_unix\.so)\ s+)(.*)$/\1\4 remember=${nr}/" $PTF

authselect apply-changes

exit 0
