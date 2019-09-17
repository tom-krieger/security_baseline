require 'facter/helpers/check_kernel_module'

# frozen_string_literal: true

# tipc.rb
# Check if tipc module is present

Facter.add('net_tipc') do
  confine kernel: 'Linux'
  setcode do
    check_kernel_module('tipc')
  end
end
