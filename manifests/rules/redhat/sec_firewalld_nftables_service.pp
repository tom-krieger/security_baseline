# @summary 
#    Ensure nftables is not enabled (Scored)
#
# nftables is a subsystem of the Linux kernel providing filtering and classification of network 
# packets/datagrams/frames and is the successor to iptables.
# nftables are installed as a dependency with firewalld.
#
# Rationale:
# Running firewalld and nftables concurrently may lead to conflict, therefore nftables should be 
# stopped and masked when using firewalld.
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
#   class security_baseline::rules::redhat::sec_firewalld_nftables_service {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::redhat::sec_firewalld_nftables_service (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
) {
  if ($enforce) {
    if(!defined(Service['nftables'])) {
      Service { 'nftables':
        ensure => stopped,
        enable => false,
      }
    }
  } else {
    if ($facts['security_baseline']['services_enabled']['srv_nftables'] == true) {
      echo { 'firewalld-nftables-service':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
