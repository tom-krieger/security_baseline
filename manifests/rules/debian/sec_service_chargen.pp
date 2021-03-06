# @summary 
#    Ensure chargen services are not enabled (Scored)
#
# chargen is a network service that responds with 0 to 512 ASCII characters for each connection 
# it receives. This service is intended for debugging and testing purposes. It is recommended 
# that this service be disabled.
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
#   class security_baseline::rules::debian::sec_service_chargen {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::debian::sec_service_chargen (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if(has_key($facts['security_baseline']['inetd_services'], 'srv_chargen')) {
    if($enforce) {
      if($facts['security_baseline']['inetd_services']['srv_chargen']['status']) {
        file_line { 'chargen_disable':
          line     => 'disable     = yes',
          path     => $facts['security_baseline']['inetd_services']['srv_chargen']['filename'],
          match    => 'disable.*=',
          multiple => true,
        }
      }
    } else {
      if($facts['security_baseline']['inetd_services']['srv_chargen']['status']) {
        echo { 'chargen-inetd':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
    }
  }
}
