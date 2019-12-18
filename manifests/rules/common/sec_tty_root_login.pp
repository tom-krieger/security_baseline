# @summary 
#    Ensure root login is restricted to system console (Not Scored)
#
# The file /etc/securetty contains a list of valid terminals that may be logged in directly as root.
#
# Rationale:
# Since the system console has special properties to handle emergency situations, it is important to ensure 
# that the console is in a physically secure location and that unauthorized consoles have not been defined.
#
## @param enforce
#    Enforce the rule or just test and log
#
# @param message
#    Message to print into the log
#
# @param log_level
#    The log_level for the above message
#
# @example
#   class security_baseline::rules::common::sec_tty_root_login {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_tty_root_login (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
) {
  echo { 'root-tty-console':
    message  => $message,
    loglevel => $log_level,
    withpath => false,
  }
}
