# frozen_string_literal: true

# rsyncd_service.rb
# Check if rsyncd services is enabled

Facter.add('srv_rsyncd') do
  confine :osfamily => 'RedHat'
  setcode do
    ret = ''
    rsyncd = Facter::Core::Execution.exec('systemctl is-enabled rsyncd')
    if (rsyncd =~ %r{^Failed}) or (rsyncd.empty?) then
      ret = 'disabled'
    else
      ret = rsyncd
    end

    ret
  end
end
      