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
# @param log_level
#    The log_level for the above message
#
# @example
#   class security_baseline::rules::common::sec_net_sctp {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_net_sctp (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if $enforce {
    kmod::install { 'sctp':
      command => '/bin/true',
    }
  } else {

    if($facts['security_baseline']['kernel_modules']['sctp']) {
      echo { 'sctp':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
