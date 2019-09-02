require 'facter/helpers/check_kernel_module'

# frozen_string_literal: true

# cramfs.rb
# Check if chargen services are switched on
Facter.add('kmod_cramfs') do
  confine :kernel => 'Linux'
  setcode do
    check_kernel_module('cramfs')
  end
end
