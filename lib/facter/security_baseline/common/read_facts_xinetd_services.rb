# get facts about xinetd services

def read_facts_xinetd_services
  xinetd_services = {}
  srvs = ['echo', 'time', 'chargen', 'tftp', 'daytime', 'discard']

  srvs.each do |srv|
    srv_name = "srv_#{srv}"
    xinetd_services[srv_name] = check_xinetd_service(srv)
  end

  xinetd_services
end
