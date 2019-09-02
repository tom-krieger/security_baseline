# @summary 
#    Ensure /etc/hosts.deny is configured (Scored)
#
# The /etc/hosts.deny file specifies which IP addresses are not permitted to connect to the host. 
# It is intended to be used in conjunction with the /etc/hosts.allow file.
# 
# Rationale:
# The /etc/hosts.deny file serves as a failsafe so that any host not specified in /etc/hosts.allow 
# is denied access to the system.
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
#   class security_baseline::rules::sec_hosts_deny {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_hosts_deny (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    file { '/etc/hosts.deny':
      ensure  => file,
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => 'ALL:ALL',
    }

  } else {

    if($::sec_hosts_deny == false) {
      echo { 'hosts-deny':
        message  => $message,
        loglevel => $loglevel,
      }
    }
  }
}
