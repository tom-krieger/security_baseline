# frozen_string_literal: true

# squid_service.rb
# Check if squid services is enabled

Facter.add('srv_squid') do
  confine :osfamily => 'RedHat'
  setcode do
    check_service_is_enabled('squid')
  end
end
  