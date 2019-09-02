# check if a systemd service is enabled
def check_service_is_enabled(service)

  srv = Facter::Core::Execution.exec("systemctl is-enabled #{srv}")
  if (srv =~ %r{^Failed}) or (srv.empty?) then
    ret = 'disabled'
  else
    ret = srv
  end

  ret
end

# check if an xinetd servicve is enabled
def check_xinetd_service(service)

  ret = false
  srv = Facter::Core::Execution.exec("chkconfig --list 2>/dev/null | grep #{service}")
  if srv.empty? then
    ret = false
  else
    srvs = srv.split("\n")
    srvs.each do |line|
      data = line.strip().split(%r{:})
      if data[1].strip().downcase() != 'off' then
        ret = true
      end
    end
  end

  ret
end
