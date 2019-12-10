# @summary 
#    Ensure no ungrouped files or directories exist (Scored)
#
# Sometimes when administrators delete users or groups from the system they neglect to remove all 
# files owned by those users or g
# 
# Rationale:
# A new user who is assigned the deleted user's user ID or group ID may then end up "owning" these files, 
# and thus have more access on the system than was intended.
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
#   class security_baseline::rules::common::sec_ungrouped_files {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_ungrouped_files (
  $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if ($facts['security_baseline']['file_permissions']['ungrouped_count'] != 0) {
    echo { 'ungrouped_files':
      message  => $message,
      loglevel => $log_level,
      withpath => false,
    }
  }
}
