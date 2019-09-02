def check_service_is_enabled(service)

  srv = Facter::Core::Execution.exec("systemctl is-enabled #{srv}")
  if (srv =~ %r{^Failed}) or (srv.empty?) then
    ret = 'disabled'
  else
    ret = srv
  end

  ret
end