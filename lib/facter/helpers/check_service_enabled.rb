# check if a systemd service is enabled
def check_service_is_enabled(service)
  srv = Facter::Core::Execution.exec("systemctl is-enabled #{service}")
  if (srv =~ %r{^Failed}) || srv.empty?
    'disabled'
  else
    srv
  end
end

# check if an xinetd servicve is enabled
def check_xinetd_service(service)
  ret = false
  srv = Facter::Core::Execution.exec("chkconfig --list 2>/dev/null | grep #{service}")
  if srv.empty?
    ret = false
  else
    srvs = srv.split("\n")
    srvs.each do |line|
      data = line.split(%r{:})
      if data[1].casecmp('off') != 0
        ret = true
      end
    end
  end

  ret
end
