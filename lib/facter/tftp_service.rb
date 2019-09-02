require 'facter/check_service_enabled'

# frozen_string_literal: true

# tftp_service.rb
# Check if tftp services are switched on

Facter.add('srv_tftp') do
    confine :osfamily => 'RedHat'
    setcode do
      check_xinetd_service(>'tftp')
    end
  end
  