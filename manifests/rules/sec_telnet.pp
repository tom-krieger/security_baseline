# @summary 
#    Ensure telnet server is not enabled (Scored)
#
# The telnet-server package contains the telnet daemon, which accepts connections from users 
# from other systems via the telnet protocol.
#
# Rationale:
# The telnet protocol is insecure and unencrypted. The use of an unencrypted transmission medium 
# could allow a user with access to sniff network traffic the ability to steal credentials. The 
# ssh package provides an encrypted session and stronger security.
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
#   class security_baseline::rules::sec_telnet {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_telnet (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    service {'telnet.socket':
      ensure => 'stopped',
      enable => false
      }

  } else {

    if($::srv_telnet == 'enabled') {
      echo { 'telnet':
        message   => $message,
        log_level => $log_level,
        withpath  => false,
      }
    }
  }
}
