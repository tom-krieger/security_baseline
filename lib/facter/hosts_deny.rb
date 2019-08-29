# frozen_string_literal: true

# hosts_deny.rb
# Returns true if /etc/hosts.deny file exists
Facter.add('hosts_deny') do
  confine :osfamily => 'Linux'
  setcode do
    File.exist?('/etc/hosts.deny')
  end
end
