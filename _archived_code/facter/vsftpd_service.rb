# frozen_string_literal: true

# vsftpd_service.rb
# Check if vsftpd services is enabled

Facter.add('srv_vsftpd') do
  confine osfamily: 'RedHat'
  setcode do
    check_service_is_enabled('vsftpd')
  end
end
