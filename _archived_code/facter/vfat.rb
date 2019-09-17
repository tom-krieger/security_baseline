require 'facter/helpers/check_kernel_module'

# frozen_string_literal: true

# vfat.rb
# Check if vfat module is present

Facter.add('kmod_vfat') do
  confine kernel: 'Linux'
  setcode do
    check_kernel_module('vfat')
  end
end
