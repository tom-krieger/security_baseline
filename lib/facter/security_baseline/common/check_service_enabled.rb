# check if a systemd service is enabled
def check_service_is_enabled(service)
  srv = Facter::Core::Execution.exec("systemctl is-enabled #{service}")
  if srv.nil? || srv.empty? || (srv =~ %r{^Failed}) || srv =~ %r{Failed to get unit file state}
    'disabled'
  else
    srv
  end
end

# check if an xinetd servicve is enabled
def check_xinetd_service(service, type = 'std')
  ret = false
  if type == 'ubuntu'
    ret = check_xinetd_service_ubuntu(service)
  else
    srv = Facter::Core::Execution.exec("chkconfig --list 2>/dev/null | grep #{service}:")
    if srv.nil? || srv.empty?
      ret = false
    else
      srvs = srv.split("\n")
      srvs.each do |line|
        data = line.split(%r{:})
        data[1].strip!
        if data[1].casecmp('off') != 0
          ret = true
        end
      end
    end
  end

  ret
end

# check xinetd services for ubuntu
def check_xinetd_service_ubuntu(service)
  val = Facter::Core::Execution.exec("grep -R \"^#{service}\" /etc/inetd.*")
  ret = if val.nil? || val.empty? || val.match(%r{No such file})
          check_xinetd_files(service)
        else
          true
        end

  ret
end

# check for service files
def check_xinetd_files(service)
  val = Facter::Core::Execution.exec("grep 'disable.*= /etc/xinetd.d/#{service}")
  if val.nil? || val.empty?
    ret = false
  else
    ret = true
    lines = val.split("\n")
    lines.each do |line|
      m = line.match(%r{disable\s*=\s*(?<status>\w)})
      status = m[:status].strip.downcase
      if status == 'yes'
        ret = false
      end
    end
  end

  ret
end
