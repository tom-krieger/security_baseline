# @summary 
#    Ensure telnet server is not enabled (Scored)
#
# The telnet-server package contains the telnet daemin, which accepts connections from users from
# other systems via the telnet protocol.
# 
# Rationale:
# The telnet protocol is insecure and unencrypted. Theuse of an unencrypted transmission medium could
# allow a user with access to sniff network trafic the ability to steal credentialds. The ssh package
# provides an encrypted session and stronger security.
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
#   class security_baseline::rules::debian::sec_service_telnet {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::debian::sec_service_telnet (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if(has_key($facts['security_baseline']['inetd_services'], 'srv_chargen')) {
    if($enforce) {
      if($facts['security_baseline']['inetd_services']['srv_telnet']['status']) {
        file_line { 'telnet_disable':
          line     => 'disable     = yes',
          path     => $facts['security_baseline']['inetd_services']['srv_telnet']['filename'],
          match    => 'disable.*=',
          multiple => true,
        }
      }
    } else {
      if($facts['security_baseline']['inetd_services']['srv_telnet']['status']) {
        echo { 'telnet-inetd':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
    }
  }
}
