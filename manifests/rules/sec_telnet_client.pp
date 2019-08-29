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
# @param loglevel
#    The loglevel for the above message
#
# @example
#   class security_baseline::rules::sec_telnet_client {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_telnet_client (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    package { 'telnet':
      ensure => purged,
    }

  } else {

    if($::telnet_pkg) {

      notify { 'telnet-client':
        message  => $message,
        loglevel => $loglevel,
      }

    }

  }
}
