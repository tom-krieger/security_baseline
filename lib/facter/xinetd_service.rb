# frozen_string_literal: true

# xinetd_service.rb
# Check if xinetd services are switched on

Facter.add('srv_xinetd') do
  confine :osfamily => 'RedHat'
  setcode do
    srv = Facter::Core::Execution.exec('systemctl is-enabled xinetd')
    if srv.empty? then
      false
    else
      if srv == 'disabled' then
        false
      else
        true
      end
    end
  end
end
  