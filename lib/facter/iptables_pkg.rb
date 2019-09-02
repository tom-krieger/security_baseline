require 'facter/helpers/check_package_installed'

# frozen_string_literal: true

# iptables_pkg.rb
# Check if iptables package is installed

Facter.add('iptables_pkg') do
  confine :osfamily => 'RedHat'
  setcode do
    check_package_installed('iptables')
  end
end
 