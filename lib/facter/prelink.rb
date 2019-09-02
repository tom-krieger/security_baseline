require 'facter/helpers/check_package_installed'

# frozen_string_literal: true

# prelink.rb
# Check if prelink package is installed

Facter.add('prelink_pkg') do
  confine :osfamily => 'RedHat'
  setcode do
    check_package_installed('prelink')
  end
end
