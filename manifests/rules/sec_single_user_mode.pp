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
# @param loglevel
#    The loglevel for the above message
#
# @example
#   class security_baseline::rules::sec_single_user_mode {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_single_user_mode (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
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

    if(($::single_user_mode_emergency == false) or ($::single_user_mode_rescue == false)) {

      notify { 'sticky-ww':
        message  => $message,
        loglevel => $loglevel,
      }
    }
  }
}
