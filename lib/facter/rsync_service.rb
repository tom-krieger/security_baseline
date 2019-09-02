require 'facter/check_service_enabled'

# frozen_string_literal: true

# rsyncd_service.rb
# Check if rsyncd services is enabled

Facter.add('srv_rsyncd') do
  confine :osfamily => 'RedHat'
  setcode do
    check_service_is_enabled('rsyncd')
  end
end
      