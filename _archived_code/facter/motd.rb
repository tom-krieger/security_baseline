# frozen_string_literal: true

# motd.rb
# Ensures motd is properly configured

Facter.add('motd') do
  confine osfamily: 'RedHat'
  setcode "egrep '(\\\\v|\\\\r|\\\\m|\\\\s)' /etc/motd"
end
