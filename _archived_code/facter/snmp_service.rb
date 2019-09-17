require 'facter/helpers/check_service_enabled'

# frozen_string_literal: true

# snmp_service.rb
# Check if snmp services is enabled

Facter.add('srv_snmpd') do
  confine osfamily: 'RedHat'
  setcode do
    check_service_is_enabled('snmpd')
  end
end
