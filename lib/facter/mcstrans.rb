# frozen_string_literal: true

# mctrans.rb
# Check if mcstrans package is installed

Facter.add('mcstrans_pkg') do
  confine :osfamily => 'RedHat'
  setcode do
      val = Facter::Core::Execution.exec("rpm -q mcstrans")
      if val.empty? or val =~ %r{not installed} then
        false
      else
        true
      end
  end
end
