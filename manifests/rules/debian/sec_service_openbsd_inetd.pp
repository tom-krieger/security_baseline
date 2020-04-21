# @summary 
#    Ensure openbsd-inetd is not installed (Scored)
#
# The inetd daemon listens for well known services and dispatches the appropriate daemon to properly 
# respond to service requests.
#
# Rationale:
# If there are no inetd services required, it is recommended that the daemon be removed.
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
#   class security_baseline::rules::debian::sec_service_echo {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::debian::sec_service_openbsd_inetd (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    if!(defined(Package['openbsd-inetd'])) {
      Package { 'openbsd-inetd':
        ensure => absent,
      }
    }
  } else {
    if($facts['security_baseline']['packages_installed']['openbsd-inetd']) {
      echo { 'openbsd-inetd':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
