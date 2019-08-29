# frozen_string_literal: true

# ntalk_service.rb
# Check if ntalk services is enabled

Facter.add('srv_ntalk') do
  confine :osfamily => 'RedHat'
  setcode do
    ret = ''
    ntalk = Facter::Core::Execution.exec('systemctl is-enabled ntalk')
    if (ntalk =~ %r{^Failed}) or (ntalk.empty?) then
      ret = 'disabled'
    else
      ret = ntalk
    end

    ret
  end
end
      