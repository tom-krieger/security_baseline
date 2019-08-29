# frozen_string_literal: true

# gnome_gdm.rb
# Returns true if GNOME is installed
Facter.add('gnome_gdm') do
  confine :osfamily => 'RedHat'
  setcode do
    Facter::Core::Execution.exec('rpm -qa | grep gnome') != ''
  end
end
