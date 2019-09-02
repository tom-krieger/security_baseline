require 'facter/check_service_enabled'

# frozen_string_literal: true

# echo_service.rb
# Check if echo services are switched on

Facter.add('srv_echo') do
    confine :osfamily => 'RedHat'
    setcode do
      check_xinetd_service('echo')
    end
  end
  