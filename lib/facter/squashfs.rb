require 'facter/helpers/check_kernel_module'

# frozen_string_literal: true

# squshfs.rb
# Check if squashfs module is present

Facter.add('kmod_squashfs') do
  confine :kernel => 'Linux'
  setcode do
    check_kernel_module('squashfs')
  end
end
  