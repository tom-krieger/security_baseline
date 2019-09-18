# @summary 
#    Ensure IPv6 router advertisements are not accepted (Not Scored)
#
# This setting disables the system's ability to accept IPv6 router advertisements.
#
# Rationale:
# It is recommended that systems not accept router advertisements as they could be tricked into routing 
# traffic to compromised machines. Setting hard routes within the system (usually a single default route 
# to a trusted router) protects the system from bad routes.
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
#   class security_baseline::rules::sec_network_ipv6_router_advertisements {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_network_ipv6_router_advertisements (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    sysctl {
      'net.ipv6.conf.all.accept_ra':
        value => 0;
      'net.ipv6.conf.default.accept_ra':
        value => 0;
    }

  } else {

    if(has_key($::network_parameters, 'net.ipv6.conf.all.accept_ra' )) {
      $fact = $::network_parameters['net.ipv6.conf.all.accept_ra']
    } else {
      $fact = ''
    }
    if(has_key($::network_parameters, 'nenet.ipv6.conf.default.accept_ra')) {
      $fact_default = $::network_parameters['net.ipv6.conf.default.accept_ra']
    } else {
      $fact_default = ''
    }
    if(($fact != '0') or ($fact_default != '0')) {
      echo { 'net.ipv6.conf.all.accept_ra':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
