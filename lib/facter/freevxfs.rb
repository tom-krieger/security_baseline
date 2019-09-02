# frozen_string_literal: true

# freevxfs.rb
# Check if freevxfs module is present

Facter.add('kmod_freevxfs') do
  confine :kernel => 'Linux'
  setcode do
    check_kernel_module('freevxfs')
  end
end
