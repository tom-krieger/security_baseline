# @summary 
#    Ensure no users have .netrc files (Scored)
#
# The .netrc file contains data for logging into a remote host for file transfers via FTP. 
#
# Rationale:
# The .netrc file presents a significant security risk since it stores passwords in unencrypted form. Even if FTP is 
# disabled, user accounts may have brought over .netrc files from other systems which could pose a risk to those systems.
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
#   class security_baseline::rules::common::sec_users_netrc_files {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_users_netrc_files (
  $enforce          = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {

  } else {
    if ($facts['security_baseline']['netrc_files'] != 'none') {
      echo { 'user-netrc-files':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
