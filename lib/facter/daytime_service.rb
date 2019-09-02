require 'facter/check_service_enabled'

# frozen_string_literal: true

# daytime_service.rb
# Check if daytime services are switched on

Facter.add('srv_daytime') do
    confine :osfamily => 'RedHat'
    setcode do
      check_xinetd_service('daytime')
    end
  end
  