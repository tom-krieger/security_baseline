require 'facter/helpers/check_service_enabled'

# frozen_string_literal: true

# nfs_service.rb
# Check if nfs and rpcbind services is enabled

Facter.add('srv_nfs') do
  confine osfamily: 'RedHat'
  setcode do
    ret = 'disabled'
    nfs = check_service_is_enabled('nfs')
    nfsserver = check_service_is_enabled('nfs-server')
    rpcbind = check_service_is_enabled('rpcbind')

    if (nfs != 'disabled') || (nfsserver != 'disabled') || (rpcbind != 'disabled')
      ret = 'enabled'
    end

    ret
  end
end
