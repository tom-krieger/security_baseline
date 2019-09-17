require 'facter/helpers/check_package_installed'

# frozen_string_literal: true

# setroubleshoot.rb
# Check if setroubleshoot package is installed

Facter.add('setroubleshoot_pkg') do
  confine osfamily: 'RedHat'
  setcode do
    check_package_installed('setroubleshoot')
  end
end
