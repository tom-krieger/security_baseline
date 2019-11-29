# @summary 
#    Ensure users own their home directories (Scored)
#
# The user home directory is space defined for the particular user to set local environment variables and to store 
# personal files.
#
# Rationale:
# Since the user is accountable for files stored in the user home directory, the user must be the owner of the directory.
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
#   class security_baseline::rules::redhat::ssec_home_dirs_owner {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_home_dirs_owner (
  $enforce          = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {

  } else {
    if ($facts['security_baseline']['home_dir_owners'] != 'none') {
      echo { 'home-dir-perms':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
