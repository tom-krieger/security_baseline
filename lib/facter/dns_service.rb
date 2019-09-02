# frozen_string_literal: true

# dns_service.rb
# Check if dns services is enabled

Facter.add('srv_dns') do
  confine :osfamily => 'RedHat'
  setcode do
    check_service_is_enabled('named')
  end
end
    