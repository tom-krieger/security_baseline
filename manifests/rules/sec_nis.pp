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
# @param loglevel
#    The loglevel for the above message
#
# @example
#   class security_baseline::rules::sec_nis {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_nis (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    service {'ypserv':
      ensure => 'stopped',
      enable => false
      }

  } else {

    if($::srv_ypserv == 'enabled') {
      notify { 'ypserv':
        message  => $message,
        loglevel => $loglevel,
      }
    }
  }
}
