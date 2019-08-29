# frozen_string_literal: true

# avahi_service.rb
# Check if cups services is enabled

Facter.add('srv_cups') do
    confine :osfamily => 'RedHat'
    setcode do
      ret = ''
      cups = Facter::Core::Execution.exec('systemctl is-enabled cups')
      if (cups =~ %r{^Failed}) or (cups.empty?) then
        ret = 'disabled'
      else
        ret = cups
      end
  
      ret
    end
  end
    