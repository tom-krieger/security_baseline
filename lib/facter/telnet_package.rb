# frozen_string_literal: true

# telnet_package.rb
# Check if telnet package is installed

Facter.add('telnet_pkg') do
  confine :osfamily => 'RedHat'
  setcode do
      val = Facter::Core::Execution.exec("rpm -q telnet")
      if val.empty? or val =~ %r{not installed} then
        false
      else
        true
      end
  end
end
