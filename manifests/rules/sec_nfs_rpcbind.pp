# @summary 
#    Ensure NFS and RPC are not enabled (Scored)
#
# The Network File System (NFS) is one of the first and most widely distributed file systems in the 
# UNIX environment. It provides the ability for systems to mount file systems of other servers through 
# the network.
#
# Rationale:
# If the system does not export NFS shares or act as an NFS client, it is recommended that these services 
# be disabled to reduce remote attack surface.
#
# @param enforce
#    Enforce the rule or just test and log
#
# @param message
#    Message to print into the log
#
# @param loglevel
#    The loglevel for the above message
#
# @example
#   class security_baseline::rules::sec_nfs_rpcbind {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_nfs_rpcbind (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    service {'nfs':
      ensure => 'stopped',
      enable => false
    }
    service {'nfs-server':
      ensure => 'stopped',
      enable => false
    }
    service {'rpcbind':
      ensure => 'stopped',
      enable => false
    }

  } else {

    if($::srv_nfs == 'enabled') {
      notify { 'nfs':
        message  => $message,
        loglevel => $loglevel,
      }
    }
  }
}
