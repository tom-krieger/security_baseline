require 'facter/helpers/check_kernel_module'

# frozen_string_literal: true

# rds.rb
# Check if rds module is present

Facter.add('net_rds') do
  confine kernel: 'Linux'
  setcode do
    check_kernel_module('rds')
  end
end
