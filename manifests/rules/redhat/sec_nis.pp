# @summary 
#    Ensure NIS Server is not enabled (Scored)
#
# The Network Information Service (NIS) (formally known as Yellow Pages) is a client-server directory 
# service protocol for distributing system configuration files. The NIS server is a collection of 
# programs that allow for the distribution of configuration files.
#
# Rationale:
# The NIS service is inherently an insecure system that has been vulnerable to DOS attacks, buffer 
# overflows and has poor authentication for querying NIS maps. NIS generally been replaced by such 
# protocols as Lightweight Directory Access Protocol (LDAP). It is recommended that the service be 
# disabled and other, more secure services be used.
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
#   class security_baseline::rules::redhat::sec_nis {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_nis (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    service {'ypserv':
      ensure => 'stopped',
      enable => false
      }

  } else {

    if($facts['security_baseline']['services_enabled']['srv_ypserv'] == 'enabled') {
      echo { 'ypserv':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
