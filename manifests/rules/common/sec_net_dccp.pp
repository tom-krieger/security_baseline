# @summary 
#    Ensure DCCP is disabled (Not Scored)
#
# The Datagram Congestion Control Protocol (DCCP) is a transport layer protocol that supports 
# streaming media and telephony. DCCP provides a way to gain access to congestion control, without 
# having to do it at the application layer, but does not provide in- sequence delivery.
#
# Rationale:
# If the protocol is not required, it is recommended that the drivers not be installed to reduce the 
# potential attack surface.
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
#   class security_baseline::rules::common::sec_net_dccp {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_net_dccp (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if $enforce {
    kmod::install { 'dccp':
      command => '/bin/true',
    }
  } else {

    if($facts['security_baseline']['kernel_modules']['dccp']) {
      echo { 'dccp':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
