# frozen_string_literal: true

# dhcpd_service.rb
# Check if dhcpd services is enabled

Facter.add('srv_dhcpd') do
  confine :osfamily => 'RedHat'
  setcode do
    ret = ''
    dhcpd = Facter::Core::Execution.exec('systemctl is-enabled dhcpd')
    if (dhcpd =~ %r{^Failed}) or (dhcpd.empty?) then
      ret = 'disabled'
    else
      ret = dhcpd
    end

    ret
  end
end
  