require 'facter/check_kernel_module'

# frozen_string_literal: true

# dccp.rb
# Check if dccp module is present

Facter.add('net_dccp') do
  confine :kernel => 'Linux'
  setcode do
    check_kernel_module('dccp')
  end
end
  