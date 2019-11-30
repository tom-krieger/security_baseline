# get facts about xinetd services

def read_facts_xinetd_services(srvs)
  xinetd_services = {}

  srvs.each do |srv|
    srv_name = "srv_#{srv}"
    xinetd_services[srv_name] = check_xinetd_service(srv)
  end

  xinetd_services
end
