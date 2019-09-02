# frozen_string_literal: true

# tcp_warppers.rb
# Check if setroubleshoot package is installed

Facter.add('tcp_wrappers_pkg') do
  confine :osfamily => 'RedHat'
  setcode do
    check_package_installed('tcp_wrappers')
  end
end
