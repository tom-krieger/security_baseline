# frozen_string_literal: true

# talk_package.rb
# Check if talk package is installed

Facter.add('talk_pkg') do
  confine :osfamily => 'RedHat'
  setcode do
      val = Facter::Core::Execution.exec("rpm -q talk")
      if val.empty? or val =~ %r{not installed} then
        false
      else
        true
      end
  end
end
