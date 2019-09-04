# frozen_string_literal: true

# time_service.rb
# Check if time services are switched on

Facter.add('srv_time') do
  confine osfamily: 'RedHat'
  setcode do
    check_xinetd_service('time')
  end
end
