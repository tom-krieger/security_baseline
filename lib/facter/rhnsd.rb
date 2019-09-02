# frozen_string_literal: true

# rhnsd.rb
# Ensures there are no duplicate UIDs in /etc/passwd
Facter.add('rhnsd') do
  confine :osfamily => 'RedHat'
  setcode do
    check_service_is_enabled('rhnsd')
  end
end
