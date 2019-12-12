def read_service_data(services, file_name)
  srv_name = ''
  srv_status = ''
  srv_id = ''
  File.readlines(file_name).each do |line|
    next if line.match(%r{^$}) || line.match(%r{^#})
    if line =~ %r{^service}
      m = line.match(%r{service\s*(?<name>\w)})
      srv_name = m[:name]
    elsif line =~ %r{disable\s*=}
      m = line.match(%r{disable\s*=\s*(?<status>\w)})
      srv_status = m[:status]
    elsif line =~ %r{id\s*=}
      m = line.match(%r{id=\s*=\s*(?<id>\w)})
      srv_id = m[:id]
    elsif line =~ %r{^\}}
      services["srv_#{srv_id}"] = !srv_status.casecmp('yes').zero?
      srv_name = ''
      srv_status = ''
      srv_id = ''
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
