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
#   class security_baseline::rules::sles::sec_single_user_mode {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sles::sec_single_user_mode (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    file_line { 'su-rescue':
      path  => '/usr/lib/systemd/system/rescue.service',
      line  => 'ExecStart=-/bin/sh -c \"/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\"',
      match => '^ExecStart=',
    }
    file_line { 'su-emergency':
      path  => '/usr/lib/systemd/system/emergency.service',
      line  => 'ExecStart=-/bin/sh -c \"/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\"',
      match => '^ExecStart=',
    }
  } else {
    if($facts['security_baseline']['single_user_mode']['status'] == false) {
      echo { 'single_user_mode':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
