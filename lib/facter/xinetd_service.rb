# frozen_string_literal: true

# xinetd_service.rb
# Check if xinetd services are switched on

Facter.add('srv_xinetd') do
  confine :osfamily => 'RedHat'
  setcode do
    check_service_is_enabled('xinetd')
    srv = Facter::Core::Execution.exec('systemctl is-enabled xinetd')
  end
end
  