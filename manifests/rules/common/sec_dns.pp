# @summary 
#    Ensure DNS Server is not enabled (Scored)
#
# The Domain Name System (DNS) is a hierarchical naming system that maps names to IP addresses 
# for computers, services and other resources connected to a network.
#
# Rationale:
# Unless a system is specifically designated to act as a DNS server, it is recommended that the 
# service be disabled to reduce the potential attack surface.
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
#   class security_baseline::rules::common::sec_dns {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_dns (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    service {'named':
      ensure => 'stopped',
      enable => false
    }

  } else {

    if($facts['security_baseline']['services_enabled']['srv_named'] == 'enabled') {
      echo { 'dns':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
