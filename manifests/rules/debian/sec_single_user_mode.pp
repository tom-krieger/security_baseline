# @summary 
#    Ensure authentication required for single user mode (Scored)
#
# Single user mode (rescue mode) is used for recovery when the system detects an issue during boot 
# or by manual selection from the bootloader.
#
# Rationale:
# Requiring authentication in single user mode (rescue mode) prevents an unauthorized user from 
# rebooting the system into single user to gain root privileges without credentials.
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
#   class security_baseline::rules::debian::sec_single_user_mode {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::debian::sec_single_user_mode (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($facts['security_baseline']['single_user_mode']['rootpw'] == 'none') {
    echo { 'single_user_mode':
      message  => $message,
      loglevel => $log_level,
      withpath => false,
    }
  }
}
