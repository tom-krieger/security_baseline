# frozen_string_literal: true

# ldp_client_package.rb
# Check if openldqp-clöients package is installed

Facter.add('openldap_clients_pkg') do
  confine :osfamily => 'RedHat'
  setcode do
    check_package_installed('openldap-clients')
  end
end
