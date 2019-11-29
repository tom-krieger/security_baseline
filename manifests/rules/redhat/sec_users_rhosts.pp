# @summary 
#    Ensure no users have .rhosts files (Scored)
#
# While no .rhosts files are shipped by default, users can easily create them. 
#
# Rationale:
# This action is only meaningful if .rhosts support is permitted in the file /etc/pam.conf . Even though the 
# .rhosts files are ineffective if support is disabled in /etc/pam.conf , they may have been brought over from 
# other systems and could contain information useful to an attacker for those other systems.
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
#   class security_baseline::rules::redhat::sec_users_rhosts {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_users_rhosts (
  $enforce          = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {

  } else {
    if ($facts['security_baseline']['rhosts_files'] != 'none') {
      echo { 'user-rhosts-files':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
