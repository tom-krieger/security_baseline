def read_service_data(services, file_name)
  srv_name = ''
  srv_status = ''
  srv_id = ''
  srv = false
  File.readlines(file_name).each do |line|
    next if line.match(%r{^$}) || line.match(%r{^#})
    if line =~ %r{^service}
      m = line.match(%r{service\s*(?<name>\w+)})
      srv_name = m[:name]
      srv = true
    elsif line =~ %r{disable\s*=} && srv
      m = line.match(%r{disable\s*=\s*(?<status>\w+)})
      srv_status = m[:status]
    elsif line =~ %r{id\s*=} && srv
      m = line.match(%r{id\s*=\s*(?<srvid>[A-Za-z0-9\-]+)})
      srv_id = m[:srvid]
    elsif line =~ %r{^\}} && srv
      if srv && srv_id != ''
        services["srv_#{srv_id}"] = !srv_status.casecmp('yes').zero?
      end
      srv_name = ''
      srv_status = ''
      srv_id = ''
      srv = false
    end
  end

  services
end

def read_services_debian
  services = {}

  if File.exist?('/etc/xinetd.conf')
    services = read_service_data(services, '/etc/xinetd.conf')
  end

  Dir['/etc/xinetd.d/*'].each do |file_name|
    next if File.directory? file_name
    services = read_service_data(services, "#{file_name}")
  end

  services
end
