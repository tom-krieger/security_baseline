require 'facter/get_sysctl_value'

# frozen_string_literal: true

# rkernel_aslr.rb
# Contains the available rpm gpg keys

Facter.add('kernel_aslr') do
  confine :osfamily => 'RedHat'
  setcode do
    get_sysctl_value('kernel.randomize_va_space')
  end
end
    