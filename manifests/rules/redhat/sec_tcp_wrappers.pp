# @summary 
#    Ensure TCP Wrappers is installed (Scored)
#
# TCP Wrappers provides a simple access list and standardized logging method for services capable of supporting 
## it. In the past, services that were called from inetd and xinetd supported the use of tcp wrappers. As inetd 
# and xinetd have been falling in disuse, any service that can support tcp wrappers will have the libwrap.so 
# library attached to it.
# 
# Rationale:
# TCP Wrappers provide a good simple access list mechanism to services that may not have that support built in. 
# It is recommended that all services that can support TCP Wrappers, use it.
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
#   class security_baseline::rules::redhat::sec_tcp_wrappers {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_tcp_wrappers (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    package { 'tcp_wrappers':
      ensure => installed,
    }
  } else {
    if($facts['security_baseline']['packages_installed']['tcp_wrappers'] == false) {
      echo { 'tcp_wrappers':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
