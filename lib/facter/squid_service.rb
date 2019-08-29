# frozen_string_literal: true

# squid_service.rb
# Check if squid services is enabled

Facter.add('srv_squid') do
  confine :osfamily => 'RedHat'
  setcode do
    ret = ''
    squid = Facter::Core::Execution.exec('systemctl is-enabled squid')
    if (squid =~ %r{^Failed}) or (squid.empty?) then
      ret = 'disabled'
    else
      ret = squid
    end

    ret
  end
end
  