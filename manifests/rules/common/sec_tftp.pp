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
#   class security_baseline::rules::common::sec_tftp {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_tftp (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {

    service {'tftp.socket':
      ensure => 'stopped',
      enable => false
      }

  } else {

    if($facts['security_baseline']['services_enabled']['srv_tftp.socket'] == 'enabled') {
      echo { 'tftp-server':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
