# @summary 
#    Ensure daytime services are not enabled (Scored)
#
# daytime is a network service that responds with the server's current date and time. This service 
# is intended for debugging and testing purposes. It is recommended that this service be disabled.
#
# Rationale:
# Disabling this service will reduce the remote attack surface of the system.
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
#   class security_baseline::rules::debian::sec_service_daytime {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::debian::sec_service_daytime (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    if($facts['security_baseline']['inetd_services']['srv_daytime']['status']) {
      file_line { 'daytime_disable':
        line     => 'disable     = yes',
        path     => $facts['security_baseline']['inetd_services']['srv_daytime']['filename'],
        match    => 'disable.*=',
        multiple => true,
      }
    }
  } else {
    if($facts['security_baseline']['inetd_services']['srv_daytime']['status']) {
      echo { 'daytime-inetd':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
