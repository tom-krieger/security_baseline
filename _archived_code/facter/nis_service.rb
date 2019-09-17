require 'facter/helpers/check_service_enabled'

# frozen_string_literal: true

# ypserv_service.rb
# Check if ypserv services is enabled

Facter.add('srv_ypserv') do
  confine osfamily: 'RedHat'
  setcode do
    check_service_is_enabled('ypserv')
  end
end
