#!/bin/bash

CP=$(authselect current | awk 'NR == 1 {print $3}' | grep custom/) 

for FN in system-auth password-auth; do

  [[ -z $(grep -E '^\s*password\s+sufficient\s+pam_unix.so\s+.*sha512\s*.*$' $PTF) ]] && sed - ri 's/^\s*(password\s+sufficient\s+pam_unix.so\s+)(.*)$/\1\2 sha512/' $PTF 
  
done

authselect apply-changes

exit 0
