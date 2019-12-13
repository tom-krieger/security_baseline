# @summary 
#    Ensure permissions on /etc/hosts.allow are configured (Scored)
#
# The /etc/hosts.allow file contains networking information that is used by many applications and therefore must 
# be readable for these applications to operate.
#
# Rationale:
# It is critical to ensure that the /etc/hosts.allow file is protected from unauthorized write access. Although 
# it is protected by default, the file permissions could be changed either inadvertently or through malicious 
# actions.
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
#   class security_baseline::rules::common::sec_hosts_allow_perms {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_hosts_allow_perms (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    if($facts['security_baseline']['tcp_wrappers']['hosts_allow']['combined'] != '0-0-420') {
      exec { 'set hosts.allow owner permissions':
        command => 'chown root:root /etc/hosts.allow',
        path    => ['/bin', '/sbin', '/usr/bin', '/usr/sbin'],
      }
      exec { 'set hosts.allow file permissions':
        command => 'chmod 0644 /etc/hosts.allow',
        path    => ['/bin', '/sbin', '/usr/bin', '/usr/sbin'],
      }
    }
  } else {
    if($facts['security_baseline']['tcp_wrappers']['hosts_allow']['combined'] != '0-0-420') {
      echo { 'hosts-allow-perms':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
