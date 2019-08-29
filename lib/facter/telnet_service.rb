# frozen_string_literal: true

# telnet_service.rb
# Check if telnet services is enabled

Facter.add('srv_telnet') do
  confine :osfamily => 'RedHat'
  setcode do
    ret = ''
    telnet = Facter::Core::Execution.exec('systemctl is-enabled telnet.socket')
    if (telnet =~ %r{^Failed}) or (telnet.empty?) then
      ret = 'disabled'
    else
      ret = telnet
    end

    ret
  end
end
    