# frozen_string_literal: true

# rsh_service.rb
# Check if rsh services is enabled

Facter.add('srv_rsh') do
    confine :osfamily => 'RedHat'
    setcode do
      ret = ''
      rsh = Facter::Core::Execution.exec('systemctl is-enabled rsh.socket')
      if (rsh =~ %r{^Failed}) or (rsh.empty?) then
        rsh = 'disabled'
      else
        rsh = 'enabled'
      end

      rlogin = Facter::Core::Execution.exec('systemctl is-enabled rlogin.socket')
      if (rlogin =~ %r{^Failed}) or (rlogin.empty?) then
        rlogin = 'disabled'
      else
        rlogin = 'enabled'
      end

      rexec = Facter::Core::Execution.exec('systemctl is-enabled rexec.socket')
      if (rexec =~ %r{^Failed}) or (rexec.empty?) then
        rexec = 'disabled'
      else
        rexec = 'enabled'
      end
  
      if ((rsh == 'enbaled') or (rlogin == 'enabled') or (rexec == 'enabled')) then
        ret = 'enabled'
      else
        ret = 'disabled'
      end

      ret
    end
  end
      