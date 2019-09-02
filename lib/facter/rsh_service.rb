require 'facter/check_service_enabled'

# frozen_string_literal: true

# rsh_service.rb
# Check if rsh services is enabled

Facter.add('srv_rsh') do
    confine :osfamily => 'RedHat'
    setcode do
      ret = ''
      rsh = check_service_is_enabled('rsh.socket')
      rlogin = check_service_is_enabled('rlogin.socket')
      rexec = check_service_is_enabled('recex.socket')
  
      if ((rsh == 'enbaled') or (rlogin == 'enabled') or (rexec == 'enabled')) then
        ret = 'enabled'
      else
        ret = 'disabled'
      end

      ret
    end
  end
      