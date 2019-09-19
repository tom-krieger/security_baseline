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
# @param log_level
#    The log_level for the above message
#
# @example
#   class security_baseline::rules::sec_x11_installed {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_x11_installed (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    if($facts['security_baseline']['x11-packages']) {
      package { $facts['security_baseline']['x11-packages']:
        ensure => purged,
      }
    }
  } else {

    if($facts['security_baseline']['x11-packages']) {
      echo { 'x11-installed':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
