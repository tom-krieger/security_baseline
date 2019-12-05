# @summary 
#    Ensure permissions on /etc/shadow are configured (Scored)
#
# The /etc/shadow file is used to store the information about user accounts that is critical to the security of 
# those accounts, such as the hashed password and other security information.
#
# Rationale:
# If attackers can gain read access to the /etc/shadow file, they can easily run a password cracking program against 
# the hashed password to break it. Other security information that is stored in the /etc/shadow file (such as expiration) 
# could also be useful to subvert the user accounts.
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
#   class security_baseline::rules::common::sec_shadow_perms {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_shadow_perms (
  $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {
    file { '/etc/shadow':
      ensure => present,
      owner  => 'root',
      group  => 'root',
      mode   => '0000',
    }
  } else {
    if ($facts['security_baseline']['file_permissions']['shadow']['combined'] != '0-0-0') {
      echo { 'shadow_perms':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
