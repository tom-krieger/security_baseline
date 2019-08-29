# frozen_string_literal: true

# iptables_pkg.rb
# Check if iptables package is installed

Facter.add('iptables_pkg') do
    confine :osfamily => 'RedHat'
    setcode do
        val = Facter::Core::Execution.exec("rpm -q iptables")
        if val.empty? or val =~ %r{not installed} then
          false
        else
          true
        end
    end
  end
  