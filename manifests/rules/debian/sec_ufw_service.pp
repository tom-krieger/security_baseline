# @summary 
#    Ensure ufw service is enabled (Scored)
#
# UncomplicatedFirewall (ufw) is a frontend for iptables. ufw provides a framework for managing netfilter, 
# as well as a command-line and available graphical user interface for manipulating the firewall.
#
# Ensure that the ufw service is enabled to protect your system.
#
# Rationale:
# The ufw service must be enabled and running in order for ufw to protect the system
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
#   class security_baseline::rules::debian::sec_ufw_service {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::debian::sec_ufw_service (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
) {
  if($enforce) {
    if(!defined(Service['ufw'])) {
      Service {'ufw':
        ensure => running,
        enable => true,
      }
    }
    exec { 'enable-ufw':
      command => 'ufw --force enable',
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      unless  => 'test -z "$(ufw status | grep \"Status: inactive\")"',
    }
  } else {
    if($facts['security_baseline']['services_enabled']['srv_ufw'] == 'disabled') {
      echo { 'ufw-service':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
