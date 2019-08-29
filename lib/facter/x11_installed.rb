# frozen_string_literal: true

# x11_installed.rb
# Check if X Windows is installed

Facter.add('x11_packages') do
  confine :osfamily => 'RedHat'
  setcode do
    pkgs = Facter::Core::Execution.exec('rpm -qa xorg-x11*')
    pkgs.split("\n")
  end
end
  