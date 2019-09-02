require 'facter/helpers/check_package_installed'

# frozen_string_literal: true

# rsh_package.rb
# Check if rsh package is installed

Facter.add('rsh_pkg') do
  confine :osfamily => 'RedHat'
  setcode do
    check_package_installed('rsh')
  end
end
  