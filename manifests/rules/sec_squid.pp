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
# @param loglevel
#    The loglevel for the above message
#
# @example
#   class security_baseline::rules::sec_squid {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_squid (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    service {'squid':
      ensure => 'stopped',
      enable => false
    }

  } else {

    if($::srv_squid == 'enabled') {
      echo { 'squid':
        message  => $message,
        loglevel => $loglevel,
      }
    }
  }
}
