# frozen_string_literal: true

# rsh_package.rb
# Check if rsh package is installed

Facter.add('rsh_pkg') do
  confine :osfamily => 'RedHat'
  setcode do
      val = Facter::Core::Execution.exec("rpm -q rsh")
      if val.empty? or val =~ %r{not installed} then
        false
      else
        true
      end
  end
end
  