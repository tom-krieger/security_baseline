# frozen_string_literal: true

# nfs_service.rb
# Check if nfs and rpcbind services is enabled

Facter.add('srv_nfs') do
  confine :osfamily => 'RedHat'
  setcode do
    ret = 'disabled'
    nfs = Facter::Core::Execution.exec('systemctl is-enabled nfs')
    nfsserver = Facter::Core::Execution.exec('systemctl is-enabled nfs-server')
    rpcbind = Facter::Core::Execution.exec('systemctl is-enabled rpcbind')
    if (nfs =~ %r{^Failed}) or (nfs.empty?) then
      nfs = 'disabled'
    end
    if (nfsserver =~ %r{^Failed}) or (nfsserver.empty?) then
      nfsserver = 'disabled'
    end
    if (rpcbind =~ %r{^Failed}) or (rpcbind.empty?) then
      rpcbind = 'disabled'
    end

    if (nfs != 'disabled') or (nfsserver != 'disabled') or (rpcbind != 'disabled') then
      ret = 'enabled'
    end
    ret
  end
end
    