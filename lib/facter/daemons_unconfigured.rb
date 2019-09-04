# frozen_string_literal: true

# daemons_unconfigured.rb
# Ensures no unconfined daemons exist

Facter.add('unconfigured_daemons') do
  confine osfamily: 'RedHat'
  setcode "ps -eZ | egrep \"initrc\" | egrep -vw \"tr|ps|egrep|bash|awk\" | tr ':' ' ' | awk '{ print $NF }'"
end
