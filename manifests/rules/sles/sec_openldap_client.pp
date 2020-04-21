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
# @param log_level
#    The log_level for the above message
#
# @example
#   class security_baseline::rules::sles::sec_openldap_client {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sles::sec_openldap_client (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    Package { 'openldap-clients':
      ensure => 'absent',
    }
  } else {
    if($facts['security_baseline']['packages_installed']['openldap_clients']) {
      echo { 'openldap-clients':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
