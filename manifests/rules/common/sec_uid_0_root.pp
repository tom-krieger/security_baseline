# @summary 
#    Ensure root is the only UID 0 account (Scored)
#
# Any account with UID 0 has superuser privileges on the system. 
#
# Rationale:
# This access must be limited to only the default root account and only from the system console. Administrative access 
# must be through an unprivileged account using an approved mechanism as noted in Item 5.6 Ensure access to the su 
# command is restricted.
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
#   class security_baseline::rules::common::sec_uid_o_root {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_uid_0_root (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if ($facts['security_baseline']['uid_0'] != 'root') {
    echo { 'uid_0_root':
      message  => $message,
      loglevel => $log_level,
      withpath => false,
    }
  }
}
