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
# @param loglevel
#    The loglevel for the above message
#
# @example
#   class security_baseline::rules::sec_dns {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_dns (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    service {'named':
      ensure => 'stopped',
      enable => false
    }

  } else {

    if($::srv_dns == 'enabled') {
      echo { 'dns':
        message  => $message,
        loglevel => $loglevel,
        withpath => false,
      }
    }
  }
}
