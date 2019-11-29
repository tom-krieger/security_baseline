# @summary 
#    Ensure permissions on /etc/passwd are configured (Scored)
#
# The /etc/passwd file contains user account information that is used by many system utilities and therefore must be readable 
# for these utilities to operate.
# 
# Rationale:
# It is critical to ensure that the /etc/passwd file is protected from unauthorized write access. Although it is protected by 
# default, the file permissions could be changed either inadvertently or through malicious actions.
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
#   class security_baseline::rules::redhat::sec_passwd_perms {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_passwd_perms (
  $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {
    file { '/etc/passwd':
      ensure => present,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }
  } else {
    if ($facts['security_baseline']['file_permissions']['passwd']['combined'] != '0-0-420') {
      echo { 'passwd_perms':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
