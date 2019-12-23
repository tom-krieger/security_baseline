#!/bin/bash

nr=$1

CP=$(authselect current | awk 'NR == 1 {print $3}' | grep custom/)
[[ -n $CP ]] && PTF=/etc/authselect/$CP/system-auth || PTF=/etc/authselect/system-auth
[[ -n $(grep -E '^\s*password\s+(sufficient\s+pam_unix|requi(red|site)\s+pam_pwhistory).so\s+ ([^#]+\s+)*remember=\S+\s*.*$' $PTF) ]] && sed -ri "s/^\s*(password\s+(requisite|sufficient)\s+(pam_pwquality\.so|pam_unix\.so)\s+)(.*)(remember=\S+\s*)(.*)$/\1\4 remember=${nr} \6/" $PTF || sed -ri "s/^\s*(password\s+(requisite|sufficient)\s+(pam_pwquality\.so|pam_unix\.so)\ s+)(.*)$/\1\4 remember=${nr}/" $PTF

authselect apply-changes

exit 0
