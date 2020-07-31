# @summary 
#    Ensure telnet client is not installed (Scored)
#
# The telnet package contains the telnet client, which allows users to start connections to other 
# systems via the telnet protocol.
# 
# Rationale:
# The telnet protocol is insecure and unencrypted. The use of an unencrypted transmission medium 
# could allow an unauthorized user to steal credentials. The ssh package provides an encrypted 
# session and stronger security and is included in most Linux distributions.
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
#   class security_baseline::rules::sles::sec_telnet_client {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sles::sec_telnet_client (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    ensure_packages(['telnet'], {
      ensure => 'absent',
    })
  } else {
    if($facts['security_baseline']['packages_installed']['telnet']) {
      echo { 'telnet-client':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
