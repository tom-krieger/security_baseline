# @summary 
#    Ensure DHCP Server is not enabled (Scored)
#
# The Dynamic Host Configuration Protocol (DHCP) is a service that allows machines to be dynamically assigned IP addresses.
#
# Rationale:
# Unless a system is specifically set up to act as a DHCP server, it is recommended that this service be disabled 
# to reduce the potential attack surface.
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
#   class security_baseline::rules::common::sec_dhcpd {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_dhcpd (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    unless(defined(Service['dhcpd'])) {
      service {'dhcpd':
        ensure => 'stopped',
        enable => false
      }
    }
  } else {

    if($facts['security_baseline']['services_enabled']['srv_dhcpd'] == 'enabled') {
      echo { 'dhcpd':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
