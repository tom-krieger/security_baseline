require 'facter/helpers/check_service_enabled'

# frozen_string_literal: true

# dovecot_service.rb
# Check if dovecot services is enabled

Facter.add('srv_dovecot') do
  confine :osfamily => 'RedHat'
  setcode do
    check_service_is_enabled('dovecot')
  end
end
  