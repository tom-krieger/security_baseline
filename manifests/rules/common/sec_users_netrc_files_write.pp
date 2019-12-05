# @summary 
#    Ensure users' .netrc Files are not group or world accessible (Scored)
#
# While the system administrator can establish secure permissions for users' .netrc files, the users can easily override these.
#
# Rationale:
# .netrc files may contain unencrypted passwords that may be used to attack other systems.
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
#   class security_baseline::rules::common::sec_users_netrc_files_write {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_users_netrc_files_write (
  $enforce          = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {

  } else {
    if ($facts['security_baseline']['netrc_files_write'] != 'none') {
      echo { 'user-netrc-files-write':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
