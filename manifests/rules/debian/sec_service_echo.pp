# @summary 
#    Ensure echo services are not enabled (Scored)
#
# echo is a network service that responds to clients with the data sent to it by the client. 
# This service is intended for debugging and testing purposes. It is recommended that this 
# service be disabled.
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
#   class security_baseline::rules::debian::sec_service_echo {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::debian::sec_service_echo (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if(has_key($facts['security_baseline']['inetd_services'], 'srv_echo')) {
    if($enforce) {
      if($facts['security_baseline']['inetd_services']['srv_echo']['status']) {
        file_line { 'echo_disable':
          line     => 'disable     = yes',
          path     => $facts['security_baseline']['inetd_services']['srv_echo']['filename'],
          match    => 'disable.*=',
          multiple => true,
        }
      }
    } else {
      if($facts['security_baseline']['inetd_services']['srv_echo']['status']) {
        echo { 'echo-inetd':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
    }
  }
}
