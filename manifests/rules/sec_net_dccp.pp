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
# @param loglevel
#    The loglevel for the above message
#
# @example
#   class security_baseline::rules::sec_net_dccp {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_net_dccp (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if $enforce {
    kmod::install { 'dccp':
      command => '/bin/true',
    }
  } else {

    if($::net_dccp) {
      echo { 'net-dccp':
        message  => $message,
        loglevel => $loglevel,
        withpath => false,
      }
    }
  }
}
