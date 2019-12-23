# @summary 
#    Ensure network interfaces are assigned to appropriate zone (Not Scored)
#
# firewall zones define the trust level of network connections or interfaces.
#
# Rationale:
# A network interface not assigned to the appropriate zone can allow unexpected or undesired network traffic to be accepted on the interface
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
# @param zone_config
#    firewalld interface and zone config
#
# @example
#   class security_baseline::rules::redhat::sec_firewalld_default_zone {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#       zone_config => { 'public' => 'eth0' },
#   }
#
# @api private
class security_baseline::rules::redhat::sec_firewalld_iface_assignment (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
  Hash $zone_config = {},
) {
  if ($enforce) {
    $zone_config.each |$zone, $iface| {
      if(has_key($facts['security_baseline'], 'firewalld')) {
        if(has_key($facts['security_baseline']['firewalld']['zone_iface'], $zone)) {
          if ($facts['security_baseline']['firewalld']['zone_iface'][$zone] != $iface) {
            exec { 'firewalld change zone interface':
              command => "firewall-cmd --zone=${zone} --change-interface=${iface}",
              path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            }
          }
        }
      }
    }
  } else {
    if ($facts['security_baseline']['firewalld']['zone_iface_assigned_status'] == false) {
      echo { 'firewalld-iface-assignment':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
