# @summary 
#    Ensure HTTP Proxy Server is not enabled (Scored)
#
# Squid is a standard proxy server used in many distributions and environments.
#
# Rationale:
# If there is no need for a proxy server, it is recommended that the squid proxy be disabled to 
# reduce the potential attack surface.
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
#   class security_baseline::rules::redhat::sec_squid {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_squid (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    service {'squid':
      ensure => 'stopped',
      enable => false
    }

  } else {

    if($facts['security_baseline']['services_enabled']['srv_squid'] == 'enabled') {
      echo { 'squid':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
