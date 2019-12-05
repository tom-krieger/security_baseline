# @summary 
#    Ensure permissions on /etc/passwd- are configured (Scored)
#
# The /etc/passwd- file contains backup user account information. 
#
# Rationale:
# It is critical to ensure that the /etc/passwd- file is protected from unauthorized access. Although it is protected 
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
#   class security_baseline::rules::common::sec_passwd_bak_perms {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_passwd_bak_perms (
  $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {
    file { '/etc/passwd-':
      ensure => present,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }
  } else {
    if ($facts['security_baseline']['file_permissions']['passwd-']['combined'] != '0-0-420') {
      echo { 'passwd_bak_perms':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
