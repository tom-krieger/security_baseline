# @summary 
#    Ensure nftables service is enabled (Scored)
#
# The nftables service allows for the loading of nftables rulesets during boot, or starting of the nftables service.
#
# Rationale:
# The nftables service restores the nftables rules from the rules files referenced in the /etc/sysconfig/nftables.conf 
# file durring boot or the starting of the nftables service
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
#   class security_baseline::rules::redhat::sec_nftables_base_chains {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::redhat::sec_nftables_service (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
) {
  if($enforce) {
    if(!defined(Service['nftables'])) {
      service {'nftables':
        ensure => running,
        enable => true,
      }
    }
  } else {
    if($facts['security_baseline']['services_enabled']['srv_nftables'] == false) {
      echo { 'nftables-service':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
