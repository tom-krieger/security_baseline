# frozen_string_literal: true

# tftp_server_service.rb
# Check if tftp_server services is enabled

Facter.add('srv_tftp_server') do
    confine :osfamily => 'RedHat'
    setcode do
      check_service_is_enabled('tftp.socket')
    end
  end
      