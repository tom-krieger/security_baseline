# @summary 
#    Disable IPv6 (Not Scored)
#
# Although IPv6 has many advantages over IPv4, not all organizations have IPv6 or dual stack configurations implemented.
#
# Rationale:
# If IPv6 or dual stack is not to be used, it is recommended that IPv6 be disabled to reduce the attack surface of the system.
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
#   class security_baseline::rules::redhat::sec_firewalld_service {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::redhat::sec_disable_ipv6 (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
) {
  if($enforce) {
    grub_config { 'ipv6_disable':
      value => '1'
    }
  } else {
    if($facts['security_baseline']['grub_ipv6_disabled'] == false) {
      echo { 'grub-disable-ipv6':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
