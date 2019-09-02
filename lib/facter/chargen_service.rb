require 'facter/check_service_enabled'

# frozen_string_literal: true

# chargen_service.rb
# Check if chargen services are switched on

Facter.add('srv_chargen') do
  confine :osfamily => 'RedHat'
  setcode do
    check_xinetd_service('chargen')
  end
end
