# @summary 
#    Ensure no world writable files exist (Scored)
#
# Unix-based systems support variable settings to control access to files. World writable files are the least 
# secure. See the chmod(2) man page for more information.
#
# Rationale:
# Data in world-writable files can be modified and compromised by any user on the system. World writable files may 
# also indicate an incorrectly written script or program that could potentially be the cause of a larger compromise 
# to the system's integrity.
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
#   class security_baseline::rules::redhat::sec_world_writable_files {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_world_writable_files (
  $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

  } else {
    if ($facts['security_baseline']['file_permissions']['world_writable_count'] != 0) {
      echo { 'world_writable_files':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
