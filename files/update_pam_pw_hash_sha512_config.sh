#!/bin/bash

PTF=$1

[[ -z $(grep -E '^\s*password\s+sufficient\s+pam_unix.so\s+.*sha512\s*.*$' $PTF) ]] && sed - ri 's/^\s*(password\s+sufficient\s+pam_unix.so\s+)(.*)$/\1\2 sha512/' $PTF 
  

authselect apply-changes

exit 0
