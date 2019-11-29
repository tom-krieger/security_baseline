# @summary 
#    Ensure all groups in /etc/passwd exist in /etc/group (Scored)
#
# Over time, system administration errors and changes can lead to groups being defined in /etc/passwd but not in /etc/group .
#
# Rationale:
# Groups defined in the /etc/passwd file but not in the /etc/group file pose a threat to system security since group 
# permissions are not properly managed.
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
#   class security_baseline::rules::redhat::sec_group_passwd {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_group_passwd (
  $enforce          = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {

  } else {
    if ($facts['security_baseline']['passwd_group'] != 'none') {
      echo { 'user-rhosts-files':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
