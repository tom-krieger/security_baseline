# @summary 
#    Ensure users' dot files are not group or world writable (Scored)
#
# While the system administrator can establish secure permissions for users' "dot" files, the users can 
# easily override these.
#
# Rationale:
# Group or world-writable user configuration files may enable malicious users to steal or modify other users' 
# data or to gain another user's system privileges.
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
#   class security_baseline::rules::common::sec_users_dot_files {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_users_dot_files (
  $enforce          = true,
  String $message   = '',
  String $log_level = ''
) {
  if ($facts['security_baseline']['user_dot_file_write'] != 'none') {
    echo { 'user-dot-files-write':
      message  => $message,
      loglevel => $log_level,
      withpath => false,
    }
  }
}
