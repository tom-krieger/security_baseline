require 'facter/helpers/check_package_installed'

# frozen_string_literal: true

# selinux.rb
# Check if prelink package is installed

Facter.add('selinux_pkg') do
  confine :osfamily => 'RedHat'
  setcode do
    check_package_installed('libselinux')
  end
end
