# @summary 
#    Ensure NIS Client is not installed (Scored)
#
# The Network Information Service (NIS), formerly known as Yellow Pages, is a client-server 
## directory service protocol used to distribute system configuration files. The NIS client 
# (ypbind) was used to bind a machine to an NIS server and receive the distributed configuration files.
#
# Rationale:
# The NIS service is inherently an insecure system that has been vulnerable to DOS attacks, buffer 
# overflows and has poor authentication for querying NIS maps. NIS generally has been replaced by 
# such protocols as Lightweight Directory Access Protocol (LDAP). It is recommended that the service 
# be removed.
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
#   class security_baseline::rules::sec_nis_client {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_nis_client(
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    package { 'ypbind':
      ensure => purged,
    }

  } else {

    if($::ypbind_pkg) {

      notify { 'nis-client':
        message  => $message,
        loglevel => $loglevel,
      }

    }

  }
}
