# @summary 
#    Ensure package manager repositories are configured (Not Scored)
#
# Systems need to have package manager repositories configured to ensure they receive the latest patches and updates.
#
# Rationale:
# If a system's package repositories are misconfigured important patches may not be identified or a rogue repository could 
# introduce compromised software.
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
#   class security_baseline::rules::sles::sec_zypper_repolist {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sles::sec_zypper_repolist (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($facts['security_baseline']['zypper']['repolist_config'] == false) {
    echo { 'package-repo-config':
      message  => $message,
      loglevel => $log_level,
      withpath => false,
    }
  }
}
