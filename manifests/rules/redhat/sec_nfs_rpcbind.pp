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
# @param log_level
#    The log_level for the above message
#
# @example
#   class security_baseline::rules::redhat::sec_nfs_rpcbind {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_nfs_rpcbind (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
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

    if($facts['security_baseline']['services_enabled']['srv_nfs'] == 'enabled') {
      echo { 'nfs':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
