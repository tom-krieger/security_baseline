# @summary 
#    Ensure iptables is not enabled (Scored)
#
# IPtables is an application that allows a system administrator to configure the IPv4 and IPv6 tables, 
# chains and rules provided by the Linux kernel firewall.
# IPtables is installed as a dependency with firewalld.
#
# Rationale:
# Running firewalld and IPtables concurrently may lead to conflict, therefore IPtables should be stopped 
# and masked when using firewalld.
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
#   class security_baseline::rules::redhat::sec_firewalld_iptables_service {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::redhat::sec_firewalld_iptables_service (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
) {
  if ($enforce) {
    if(!defined(Service['iptables'])) {
      ensure_resource('service', ['iptables'], {
        ensure => stopped,
        enable => false,
      })
    }
  } else {
    if ($facts['security_baseline']['services_enabled']['srv_iptables'] == true) {
      echo { 'firewalld-iptables-service':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
