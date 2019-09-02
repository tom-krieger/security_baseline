# @summary 
#    Ensure IMAP and POP3 server is not enabled (Scored)
#
# dovecot is an open source IMAP and POP3 server for Linux based systems.
#
# Rationale:
# Unless POP3 and/or IMAP servers are to be provided by this system, it is recommended that 
# the service be disabled to reduce the potential attack surface.
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
#   class security_baseline::rules::sec_dhcpd {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_dovecot (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    service {'dovecot':
      ensure => 'stopped',
      enable => false
    }

  } else {

    if($::srv_dovecot == 'enabled') {
      echo { 'sovecot':
        message  => $message,
        loglevel => $loglevel,
      }
    }
  }
}
