require 'facter/helpers/check_package_installed'

# frozen_string_literal: true

# talk_package.rb
# Check if talk package is installed

Facter.add('talk_pkg') do
  confine :osfamily => 'RedHat'
  setcode do
    check_package_installed('talk')
  end
end
