# frozen_string_literal: true

# hfs.rb
# Check if hfs module is present

Facter.add('kmod_hfs') do
  confine :kernel => 'Linux'
  setcode do
    check_kernel_module('hfs')
  end
end
