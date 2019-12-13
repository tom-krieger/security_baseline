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
# @param log_level
#    The log_level for the above message
#
# @example
#   class security_baseline::rules::common::sec_hosts_deny_perms {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_hosts_deny_perms (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    if($facts['security_baseline']['hosts_deny']['combined'] != '0-0-420') {
      exec { 'set hosts.deny owner permissions':
        command => 'chown root:root /etc/hosts.deny',
        path    => ['/bin', '/sbin', '/usr/bin', '/usr/sbin'],
      }
      exec { 'set hosts.deny file permissions':
        command => 'chmod 0644 /etc/hosts.deny',
        path    => ['/bin', '/sbin', '/usr/bin', '/usr/sbin'],
      }
    }
  } else {
    if($facts['security_baseline']['hosts_deny']['combined'] != '0-0-420') {
      echo { 'hosts-deny-perms':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
