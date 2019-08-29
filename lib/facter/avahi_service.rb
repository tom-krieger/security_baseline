# frozen_string_literal: true

# avahi_service.rb
# Check if avahi services is enabled

Facter.add('srv_avahi') do
  confine :osfamily => 'RedHat'
  setcode do
    ret = ''
    avahi = Facter::Core::Execution.exec('systemctl is-enabled avahi-daemon')
    if (avahi =~ %r{^Failed}) or (avahi.empty?) then
      ret = 'disabled'
    else
      ret = avahi
    end

    ret
  end
end
  