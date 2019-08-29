# frozen_string_literal: true

# tftp_server_service.rb
# Check if tftp_server services is enabled

Facter.add('srv_tftp_server') do
    confine :osfamily => 'RedHat'
    setcode do
      ret = ''
      tftp_server = Facter::Core::Execution.exec('systemctl is-enabled tftp.socket')
      if (tftp_server =~ %r{^Failed}) or (tftp_server.empty?) then
        ret = 'disabled'
      else
        ret = tftp_server
      end
  
      ret
    end
  end
      