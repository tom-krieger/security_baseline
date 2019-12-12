# get facts about xinetd services

def read_facts_xinetd_services(srvs, type='std')
  xinetd_services = {}

  srvs.each do |srv|
    srv_name = "srv_#{srv}"
    xinetd_services[srv_name] = check_xinetd_service(srv, type)
  end

  xinetd_services
end
