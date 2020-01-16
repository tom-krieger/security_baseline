# frozen_string_literal: true

# get facts about enabled services

def read_facts_services_enabled(services, os = '', release = '')
  services_enabled = {}

  services.each do |srv|
    srv_name = "srv_#{srv}"
    services_enabled[srv_name] = check_service_is_enabled(srv, os, release)
  end

  rsh = check_service_is_enabled('rsh.socket', os, release)
  rlogin = check_service_is_enabled('rlogin.socket', os, release)
  rexec = check_service_is_enabled('recex.socket', os, release)

  services_enabled['srv_rsh'] = if (rsh == 'enbaled') || (rlogin == 'enabled') || (rexec == 'enabled')
                                  'enabled'
                                else
                                  'disabled'
                                end

  nfs = check_service_is_enabled('nfs', os, release)
  nfsserver = check_service_is_enabled('nfs-server', os, release)
  rpcbind = check_service_is_enabled('rpcbind', os, release)

  services_enabled['srv_nfs'] = if (nfs != 'disabled') || (nfsserver != 'disabled') || (rpcbind != 'disabled')
                                  'enabled'
                                else
                                  'disabled'
                                end

  services_enabled
end
