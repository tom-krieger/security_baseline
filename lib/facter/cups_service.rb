require 'check_service_enabled.rb'

# frozen_string_literal: true

# avahi_service.rb
# Check if cups services is enabled

Facter.add('srv_cups') do
    confine :osfamily => 'RedHat'
    setcode do
      check_service_is_enabled('cups')
    end
  end
    