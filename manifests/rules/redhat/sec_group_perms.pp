# @summary 
#    Ensure permissions on /etc/group are configured (Scored)
#
# The /etc/group file contains a list of all the valid groups defined in the system. The command below 
# allows read/write access for root and read access for everyone else.
#
# Rationale:
# The /etc/group file needs to be protected from unauthorized changes by non-privileged users, but needs 
# to be readable as this information is used with many non-privileged programs.
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
#   class security_baseline::rules::redhat::sec_group_perms {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_group_perms (
  $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {
    file { '/etc/group':
      ensure => present,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }
  } else {
    if ($facts['security_baseline']['file_permissions']['group']['combined'] != '0-0-420') {
      echo { 'group_perms':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
