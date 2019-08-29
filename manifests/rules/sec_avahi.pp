# @summary 
#    Ensure Avahi Server is not enabled (Scored)
#
# Avahi is a free zeroconf implementation, including a system for multicast DNS/DNS-SD service discovery. 
# Avahi allows programs to publish and discover services and hosts running on a local network with no specific 
# configuration. For example, a user can plug a computer into a network and Avahi automatically finds printers 
# to print to, files to look at and people to talk to, as well as network services running on the machine.
#
# Rationale:
# Automatic discovery of network services is not normally required for system functionality. It is recommended 
# to disable the service to reduce the potential attack surface.
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
#   class security_baseline::rules::sec_avahi {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_avahi (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    service {'avahi-daemon':
      ensure => 'stopped',
      enable => false
      }

  } else {

    if($::srv_avahi == 'enabled') {
      notify { 'avahi-daemon':
        message  => $message,
        loglevel => $loglevel,
      }
    }
  }
}
