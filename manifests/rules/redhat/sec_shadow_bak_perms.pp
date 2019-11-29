# @summary 
#    Ensure permissions on /etc/shadow- are configured (Scored)
#
# The /etc/shadow- file is used to store backup information about user accounts that is critical to the security 
# of those accounts, such as the hashed password and other security information.
#
# Rationale:
# It is critical to ensure that the /etc/shadow- file is protected from unauthorized access. Although it is protected 
# by default, the file permissions could be changed either inadvertently or through malicious actions.
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
#   class security_baseline::rules::redhat::sec_shadow_bak_perms {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_shadow_bak_perms (
  $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {
    file { '/etc/shadow-':
      ensure => present,
      owner  => 'root',
      group  => 'root',
      mode   => '0000',
    }
  } else {
    if ($facts['security_baseline']['file_permissions']['shadow-']['combined'] != '0-0-0') {
      echo { 'shadow_bak_perms':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
