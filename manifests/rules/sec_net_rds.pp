# @summary 
#    Ensure RDS is disabled (Not Scored)
#
# The Reliable Datagram Sockets (RDS) protocol is a transport layer protocol designed to provide l
# ow-latency, high-bandwidth communications between cluster nodes. It was developed by the Oracle 
# Corporation.
#
# Rationale:
# If the protocol is not being used, it is recommended that kernel module not be loaded, disabling 
# the service to reduce the potential attack surface.
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
#   class security_baseline::rules::sec_net_rds {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_net_rds (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if $enforce {
    kmod::install { 'rds':
      command => '/bin/true',
    }
  } else {

    if($::net_rds) {
      echo { 'net-rds ':
        message  => $message,
        loglevel => $loglevel,
      }
    }
  }
}
