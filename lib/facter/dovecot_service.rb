# frozen_string_literal: true

# dovecot_service.rb
# Check if dovecot services is enabled

Facter.add('srv_dovecot') do
  confine :osfamily => 'RedHat'
  setcode do
    ret = ''
    dovecot = Facter::Core::Execution.exec('systemctl is-enabled dovecot')
    if (dovecot =~ %r{^Failed}) or (dovecot.empty?) then
      ret = 'disabled'
    else
      ret = dovecot
    end

    ret
  end
end
  