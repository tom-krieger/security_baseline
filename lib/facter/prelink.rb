# frozen_string_literal: true

# prelink.rb
# Check if prelink package is installed

Facter.add('prelink_pkg') do
  confine :osfamily => 'RedHat'
  setcode do
      val = Facter::Core::Execution.exec("rpm -q prelink")
      if val.empty? or val =~ %r{not installed} then
        false
      else
        true
      end
  end
end
