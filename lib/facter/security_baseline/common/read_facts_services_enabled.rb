# get facts about enabled services

def read_facts_services_enabled(services)
  services_enabled = {}

  services.each do |srv|
    srv_name = "srv_#{srv}"
    services_enabled[srv_name] = check_service_is_enabled(srv)
  end

  rsh = check_service_is_enabled('rsh.socket')
  rlogin = check_service_is_enabled('rlogin.socket')
  rexec = check_service_is_enabled('recex.socket')

  services_enabled['srv_rsh'] = if (rsh == 'enbaled') || (rlogin == 'enabled') || (rexec == 'enabled')
                                  'enabled'
                                else
                                  'disabled'
                                end

  nfs = check_service_is_enabled('nfs')
  nfsserver = check_service_is_enabled('nfs-server')
  rpcbind = check_service_is_enabled('rpcbind')

  services_enabled['srv_nfs'] = if (nfs != 'disabled') || (nfsserver != 'disabled') || (rpcbind != 'disabled')
                                  'enabled'
                                else
                                  'disabled'
                                end

  services_enabled
end
