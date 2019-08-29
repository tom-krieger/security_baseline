# frozen_string_literal: true

# vsftpd_service.rb
# Check if vsftpd services is enabled

Facter.add('srv_vsftpd') do
    confine :osfamily => 'RedHat'
    setcode do
      ret = ''
      vsftpd = Facter::Core::Execution.exec('systemctl is-enabled vsftpd')
      if (vsftpd =~ %r{^Failed}) or (vsftpd.empty?) then
        ret = 'disabled'
      else
        ret = vsftpd
      end
  
      ret
    end
  end
    