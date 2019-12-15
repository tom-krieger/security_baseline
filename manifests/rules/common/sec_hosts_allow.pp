# @summary 
#    Ensure /etc/hosts.allow is configured (Scored)
#
# The /etc/hosts.allow file specifies which IP addresses are permitted to connect to the host. 
# It is intended to be used in conjunction with the /etc/hosts.deny file.
#
# Rationale:
# The /etc/hosts.allow file supports access control by IP and helps ensure that only authorized 
# systems can connect to the system.
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
# @param allowd
#    Additional allow rules
#
# @example
#   class security_baseline::rules::common::sec_hosts_allow {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_hosts_allow (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
  Array $allowed    = [],
) {
  if($enforce) {
    file_line { 'allow network':
      append_on_no_match => true,
      match              => "ALL: ${facts['networking']['network']}/${facts['networking']['netmask']}",
      line               => "ALL: ${facts['networking']['network']}/${facts['networking']['netmask']}",
      path               => '/etc/hosts.allow',
    }
    $allowed.each |$allow| {
      file_line { "host allow ${allow}":
        append_on_no_match => true,
        match              => $allow,
        line               => $allow,
        path               => '/etc/hosts.allow',
      }
    }
  } else {
    if($facts['security_baseline']['tcp_wrappers']['hosts_allow']['status'] == false) {
      echo { 'hosts-allow':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
