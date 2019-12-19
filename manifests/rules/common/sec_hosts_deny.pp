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
# @param denied
#    Additional deny rules
#
# @example
#   class security_baseline::rules::common::sec_hosts_deny {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_hosts_deny (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
  Array $denied     = [],
) {
  if($enforce) {
    file_line { 'deny all':
      append_on_no_match => true,
      match              => 'ALL: ALL',
      line               => 'ALL: ALL',
      path               => '/etc/hosts.deny',
    }

    $denied.each |$deny| {
      file_line { "host deny ${deny}":
        append_on_no_match => true,
        match              => $deny,
        line               => $deny,
        path               => '/etc/hosts.deny',
      }
    }
  } else {
    if($facts['security_baseline']['tcp_wrappers']['hosts_deny']['status'] == false) {
      echo { 'hosts-deny':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
