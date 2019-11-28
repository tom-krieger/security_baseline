# @summary
#    Ensure iptables is installed (Scored)
#
# iptables allows configuration of the IPv4 tables in the linux kernel and the rules stored within them. 
# Most firewall configuration utilities operate as a front end to iptables.
#
# Rationale:
# iptables is required for firewall management and configuration.
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
#   class security_baseline::rules::redhat::sec_iptables {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_iptables (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    package { 'iptables':
      ensure => installed,
    }

  } else {

    if($facts['security_baseline']['packages_installed']['iptables'] == false) {

      echo { 'iptables':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }

    }
  }
}
