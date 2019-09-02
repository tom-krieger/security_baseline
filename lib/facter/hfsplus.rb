require 'facter/check_kernel_module'

# frozen_string_literal: true

# hfsplus.rb
# Check if hfsplus module is present

Facter.add('kmod_hfsplus') do
  confine :kernel => 'Linux'  
  setcode do
    check_kernel_module('hfsplus')
  end
end
