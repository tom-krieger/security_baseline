# @summary 
#    Ensure wireless interfaces are disabled (Not Scored)
#
# Wireless networking is used when wired networks are unavailable. Ubuntu contains a wireless tool kit 
# to allow system administrators to configure and use wireless networks.
#
# Rationale:
# If wireless is not to be used, wireless devices can be disabled to reduce the potential attack surface.
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
#   class security_baseline::rules::common::sec_wlan_interfaces {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_wlan_interfaces (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
) {
  if ($enforce) {
    if($facts['security_baseline']['wlan_interfaces_count'] != 0) {
      $facts['security_baseline']['wlan_interfaces'].each |$wlanif| {
        exec { "shutdown wlan interface ${wlanif}":
          command => "ip link set ${wlanif} down",
          path    => ['/bin', '/sbin', '/usr/bin', '/usr/sbin'],
          onlyif  => "ip link show ${wlanif} | grep 'state UP'",
        }
      }
    }
  } else {
    if($facts['security_baseline']['wlan_interfaces_count'] != 0) {
      echo { 'wlan-interfaces':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
