require 'facter/helpers/check_package_installed'

# frozen_string_literal: true

# telnet_package.rb
# Check if telnet package is installed

Facter.add('telnet_pkg') do
  confine :osfamily => 'RedHat'
  setcode do
    check_package_installed('telnet')
  end
end
