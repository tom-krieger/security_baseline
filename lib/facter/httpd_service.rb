require 'facter/helpers/check_service_enabled'

# frozen_string_literal: true

# httpd_service.rb
# Check if httpd services is enabled

Facter.add('srv_httpd') do
  confine osfamily: 'RedHat'
  setcode do
    check_service_is_enabled('httpd')
  end
end
