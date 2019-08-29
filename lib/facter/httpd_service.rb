# frozen_string_literal: true

# httpd_service.rb
# Check if httpd services is enabled

Facter.add('srv_httpd') do
    confine :osfamily => 'RedHat'
    setcode do
      ret = ''
      httpd = Facter::Core::Execution.exec('systemctl is-enabled httpd')
      if (httpd =~ %r{^Failed}) or (httpd.empty?) then
        ret = 'disabled'
      else
        ret = httpd
      end
  
      ret
    end
  end
    