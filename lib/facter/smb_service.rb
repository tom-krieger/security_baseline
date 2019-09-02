require 'facter/check_service_enabled'

# frozen_string_literal: true

# smb_service.rb
# Check if smb services is enabled

Facter.add('srv_smb') do
  confine :osfamily => 'RedHat'
  setcode do
    check_service_is_enabled('smb')
  end
end
  