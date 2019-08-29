# frozen_string_literal: true

# selinux.rb
# Check if prelink package is installed

Facter.add('selinux_pkg') do
  confine :osfamily => 'RedHat'
  setcode do
      val = Facter::Core::Execution.exec("rpm -q libselinux")
      if val.empty? or val =~ %r{not installed} then
        false
      else
        true
      end
  end
end
