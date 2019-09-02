# @summary 
#    Ensure LDAP client is not installed (Scored)
#
# The Lightweight Directory Access Protocol (LDAP) was introduced as a replacement for NIS/YP. 
# It is a service that provides a method for looking up information from a central database.
# 
# Rationale:
# If the system will not need to act as an LDAP client, it is recommended that the software 
# be removed to reduce the potential attack surface.
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
#   class security_baseline::rules::sec_openldap_client {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_openldap_client (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    package { 'openldap-clients':
      ensure => purged,
    }

  } else {

    if($::openldap_clients_pkg) {

      echo { 'openldp-clients':
        message  => $message,
        loglevel => $loglevel,
      }

    }

  }
}
