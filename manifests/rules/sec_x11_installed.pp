# @summary 
#    Ensure X Window System is not installed (Scored)
#
# The X Window System provides a Graphical User Interface (GUI) where users can have multiple 
# windows in which to run programs and various add on. The X Windows system is typically used 
# on workstations where users login, but not on servers where users typically do not login.
#
# Rationale:
# Unless your organization specifically requires graphical login access via X Windows, remove it 
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
#   class security_baseline::rules::sec_x11_installed {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_x11_installed (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    if($::x11_packages) {
      package { $::x11_packages:
        ensure => purged,
      }
    }
  } else {

    echo { 'x11-installed':
      message  => $message,
      loglevel => $loglevel,
    }

  }
}
