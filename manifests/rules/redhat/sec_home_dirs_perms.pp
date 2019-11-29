# @summary 
#    Ensure users' home directories permissions are 750 or more restrictive (Scored)
#
# While the system administrator can establish secure permissions for users' home directories, the users can easily 
# override these.
#
# Rationale:
# Group or world-writable user home directories may enable malicious users to steal or modify other users' data or to 
# gain another user's system privileges.
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
#   class security_baseline::rules::redhat::sec_home_dirs_perms {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_home_dirs_perms (
  $enforce          = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {

  } else {
    if ($facts['security_baseline']['home_dir_permissions'] != 'none') {
      echo { 'home-dir-perms':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
