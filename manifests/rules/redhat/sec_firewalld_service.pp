# @summary 
#    Ensure firewalld service is enabled and running (Scored)
#
# Ensure that the firewalld service is enabled to protect your system
#
# Rationale:
# firewalld (Dynamic Firewall Manager) tool provides a dynamically managed firewall. The tool enables network/firewall 
# zones to define the trust level of network connections and/or interfaces. It has support both for IPv4 and IPv6 firewall 
# settings. Also, it supports Ethernet bridges and allow you to separate between runtime and permanent configuration options. 
# Finally, it supports an interface for services or applications to add firewall rules directly
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
class security_baseline::rules::redhat::sec_firewalld_service (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
) {
  if ($enforce) {
    if(!defined(Service['firewalld'])) {
      ensure_resource('service', ['firewalld'], {
        ensure => running,
        enable => true,
      })
    }
  } else {
    if ($facts['security_baseline']['services_enabled']['srv_firewalld'] == false) {
      echo { 'firewalld-service':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
