# frozen_string_literal: true

# snmp_service.rb
# Check if snmp services is enabled

Facter.add('srv_snmpd') do
  confine :osfamily => 'RedHat'
  setcode do
    ret = ''
    snmp = Facter::Core::Execution.exec('systemctl is-enabled snmpd')
    if (snmp =~ %r{^Failed}) or (snmp.empty?) then
      ret = 'disabled'
    else
      ret = snmp
    end

    ret
  end
end
  