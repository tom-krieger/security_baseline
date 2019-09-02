# @summary 
#    Ensure TIPC is disabled (Not Scored)
#
# The Transparent Inter-Process Communication (TIPC) protocol is designed to provide communication between 
# cluster nodes.
# 
# Rationale:
# If the protocol is not being used, it is recommended that kernel module not be loaded, disabling the service 
# to reduce the potential attack surface.
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
#   class security_baseline::rules::sec_net_tipc {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_net_tipc (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if $enforce {
    kmod::install { 'tipc':
      command => '/bin/true',
    }
  } else {

    if($::net_tipc) {
      echo { 'net-tipc':
        message  => $message,
        loglevel => $loglevel,
        withpath => false,
      }
    }
  }
}
