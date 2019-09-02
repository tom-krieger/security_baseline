require 'facter/check_service_enabled'

# frozen_string_literal: true

# discard_service.rb
# Check if discard services are switched on

Facter.add('srv_discard') do
    confine :osfamily => 'RedHat'
    setcode do
      check_xinetd_service('discard')
    end
  end
  