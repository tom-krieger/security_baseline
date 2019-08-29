# @summary 
#    Ensure SCTP is disabled (Not Scored)
#
# The Stream Control Transmission Protocol (SCTP) is a transport layer protocol used to support 
# message oriented communication, with several streams of messages in one connection. It serves 
# a similar function as TCP and UDP, incorporating features of both. It is message-oriented like 
# UDP, and ensures reliable in-sequence transport of messages with congestion control like TCP.
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
#   class security_baseline::rules::sec_net_sctp {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_net_sctp (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if $enforce {
    kmod::install { 'sctp':
      command => '/bin/true',
    }
  } else {

    if($::net_sctp) {
      notify { 'net-sctp':
        message  => $message,
        loglevel => $loglevel,
      }
    }
  }
}
