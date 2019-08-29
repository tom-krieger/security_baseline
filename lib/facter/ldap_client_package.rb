# frozen_string_literal: true

# ldp_client_package.rb
# Check if openldqp-clöients package is installed

Facter.add('openldap_clients_pkg') do
  confine :osfamily => 'RedHat'
  setcode do
      val = Facter::Core::Execution.exec("rpm -q openldap-clients")
      if val.empty? or val =~ %r{not installed} then
        false
      else
        true
      end
  end
end
