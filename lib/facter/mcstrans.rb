require 'facter/helpers/check_package_installed'

# frozen_string_literal: true

# mctrans.rb
# Check if mcstrans package is installed

Facter.add('mcstrans_pkg') do
  confine :osfamily => 'RedHat'
  setcode do
    check_package_installed('mcstrans')
  end
end
