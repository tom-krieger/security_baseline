def read_service_data(services, file_name)
  File.readlines(file_name).each do |line|
    next if line.match(%r{^$}) || line.match(%r{^#})
    if line.match(%r{^service})
      m = line.match(%r{service\s*(?<name>\w)})
      srv_name = m[:name]
    elsif line.match(%r{disable\s*=}) 
      m = line.match(%r{disable\s*=\s*(?<status>\w)})
      srv_status = m[:status]
    elsif line.match(%r{id\s*=})
      m = line.match(%r{id=\s*=\s*(?<id>\w)})
      srv_id = m[:id]
    elsif line.match(%r{^\}})
      services["srv_#{srv_id}"] = srv_status.downcase != 'yes'
    end
  end

  services
end

def read_services_debian
  services = {}

  if File.exist('/etc/xinetd.conf')
    services = read_service_data(services, '/etc/xinetd.conf')
  end

  Dir['/etc/xinetd.d/*'].each do |file_name|
    next if File.directory? file_name 
    services = read_service_data(services, "/etc/xinetd.d/#{file_name}")
  end

  services
end
