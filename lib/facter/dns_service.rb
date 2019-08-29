# frozen_string_literal: true

# dns_service.rb
# Check if dns services is enabled

Facter.add('srv_dns') do
  confine :osfamily => 'RedHat'
  setcode do
    ret = ''
    named = Facter::Core::Execution.exec('systemctl is-enabled named')
    if (named =~ %r{^Failed}) or (named.empty?) then
      ret = 'disabled'
    else
      ret = named
    end

    ret
  end
end
    