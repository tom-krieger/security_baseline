# @summary 
#    Disable Automounting (Scored)
#
# autofs allows automatic mounting of devices, typically including CD/DVDs and USB drives.
#
# Rationale:
# With automounting enabled anyone with physical access could attach a USB drive or disc and have its 
# contents available in system even if they lacked permissions to mount it themselves.
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
#   class security_baseline::rules::sec_automounting {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_automounting (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if $enforce {

    if $::automounting == 'enabled' {

        # Why do we need to use a combination of a fact and a resource for
        # this? Why couldn't we just disable the service using a service
        # resource? Even if we were to use an exec, why are we using a fact
        # to check first? Why not use "onlyif" or "unless"?
        exec {'disable_automount':
          command => 'systemctl disable autofs',
          path    => '/bin/',
        }
      }

  } else {

    notify { 'sticky-ww':
      message  => $message,
      loglevel => $loglevel,
    }

  }
}
