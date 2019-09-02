# frozen_string_literal: true

# ypbind_package.rb
# Check if ypbind package is installed

Facter.add('ypbind_pkg') do
  confine :osfamily => 'RedHat'
  setcode do
    check_package_installed('ypbind')
  end
end
