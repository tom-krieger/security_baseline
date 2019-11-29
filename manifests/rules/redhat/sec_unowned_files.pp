# @summary 
#    Ensure no unowned files or directories exist (Scored)
#
# Sometimes when administrators delete users from the password file they neglect to remove all files owned by 
# those users from the system.
# 
# Rationale:
# A new user who is assigned the deleted user's user ID or group ID may then end up "owning" these files, and 
# thus have more access on the system than was intended.
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
#   class security_baseline::rules::redhat::sec_unowned_files {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_unowned_files (
  $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

  } else {
    if ($facts['security_baseline']['file_permissions']['unowned_count'] != 0) {
      echo { 'unowned_files':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
