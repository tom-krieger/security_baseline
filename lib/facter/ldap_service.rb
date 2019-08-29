# frozen_string_literal: true

# slapd_service.rb
# Check if slapd services is enabled

Facter.add('srv_slapd') do
  confine :osfamily => 'RedHat'
  setcode do
    ret = ''
    slapd = Facter::Core::Execution.exec('systemctl is-enabled slapd')
    if (slapd =~ %r{^Failed}) or (slapd.empty?) then
      ret = 'disabled'
    else
      ret = slapd
    end

    ret
  end
end
    