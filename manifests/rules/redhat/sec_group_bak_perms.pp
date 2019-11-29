# @summary 
#    Ensure permissions on /etc/group- are configured (Scored)
#
# The /etc/group- file contains a backup list of all the valid groups defined in the system. 
# 
# Rationale:
# It is critical to ensure that the /etc/group- file is protected from unauthorized access. Although it is protected by 
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
#   class security_baseline::rules::redhat::sec_group_bak_perms {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_group_bak_perms (
  $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {
    file { '/etc/group-':
      ensure => present,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }
  } else {
    if ($facts['security_baseline']['file_permissions']['group-']['combined'] != '0-0-420') {
      echo { 'group_bak_perms':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
