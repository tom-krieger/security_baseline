# @summary 
#    Ensure LDAP server is not enabled (Scored)
#
# The Lightweight Directory Access Protocol (LDAP) was introduced as a replacement for NIS/YP. It 
# is a service that provides a method for looking up information from a central database.
#
# Rationale:
# If the system will not need to act as an LDAP server, it is recommended that the software be 
# disabled to reduce the potential attack surface.
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
#   class security_baseline::rules::sec_ldap {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_ldap (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    service {'slapd':
      ensure => 'stopped',
      enable => false
      }

  } else {

    if($::srv_ldap == 'enabled') {
      notify { 'dhcpd':
        message  => $message,
        loglevel => $loglevel,
      }
    }
  }
}
