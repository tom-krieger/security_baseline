require 'facter/helpers/check_service_enabled'

# frozen_string_literal: true

# telnet_service.rb
# Check if telnet services is enabled

Facter.add('srv_telnet') do
  confine :osfamily => 'RedHat'
  setcode do
    check_service_is_enabled('telnet.socket')
  end
end
    