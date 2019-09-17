# frozen_string_literal: true

# hosts_allow.rb
# Returns true if /etc/hosts.allow file exists
Facter.add('hosts_allow') do
  confine kernel: 'Linux'
  setcode do
    File.exist?('/etc/hosts.allow')
  end
end
