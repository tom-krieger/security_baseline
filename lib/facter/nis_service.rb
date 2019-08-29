# frozen_string_literal: true

# ypserv_service.rb
# Check if ypserv services is enabled

Facter.add('srv_ypserv') do
  confine :osfamily => 'RedHat'
  setcode do
    ret = ''
    ypserv = Facter::Core::Execution.exec('systemctl is-enabled ypserv')
    if (ypserv =~ %r{^Failed}) or (ypserv.empty?) then
      ret = 'disabled'
    else
      ret = ypserv
    end

    ret
  end
end
      