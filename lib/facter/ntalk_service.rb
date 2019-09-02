require 'facter/helpers/check_service_enabled'

# frozen_string_literal: true

# ntalk_service.rb
# Check if ntalk services is enabled

Facter.add('srv_ntalk') do
  confine :osfamily => 'RedHat'
  setcode do
    check_service_is_enabled('ntalk')
  end
end
      