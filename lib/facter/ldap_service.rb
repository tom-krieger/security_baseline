# frozen_string_literal: true

# slapd_service.rb
# Check if slapd services is enabled

Facter.add('srv_slapd') do
  confine :osfamily => 'RedHat'
  setcode do
    check_service_is_enabled('ldap')
  end
end
    