require 'facter/check_service_enabled'

# frozen_string_literal: true

# avahi_service.rb
# Check if avahi services is enabled

Facter.add('srv_avahi') do
  confine :osfamily => 'RedHat'
  setcode do
    check_service_is_enabled('avahi-daemon')
  end
end
  