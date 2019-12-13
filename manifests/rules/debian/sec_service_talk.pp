# @summary 
#    Ensure talk server is not enabled (Scored)
#
# The talk server makes it possible for uders to send and receive messages accros systems trough
# trminal session. The talk client (allows initiate of talk sessions) is installed by default.
# 
# Rationale:
# The software presents a security risk as it uses unencrypted protocols for communication.
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
#   class security_baseline::rules::debian::sec_service_talk {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::debian::sec_service_talk (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    if($facts['security_baseline']['inetd_services']['srv_talk']['status']) {
      file_line { 'talk_disable':
        line     => 'disable     = yes',
        path     => $facts['security_baseline']['inetd_services']['srv_talk']['filename'],
        match    => 'disable.*=',
        multiple => true,
      }
    }
  } else {
    if($facts['security_baseline']['inetd_services']['srv_talk']['status']) {
      echo { 'talk-inetd':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
