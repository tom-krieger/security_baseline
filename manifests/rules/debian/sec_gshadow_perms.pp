# @summary 
#    Ensure permissions on /etc/gshadow are configured (Scored)
#
# The /etc/gshadow file is used to store the information about groups that is critical to the security of those accounts, such as 
# the hashed password and other security information.
#
# Rationale:
# If attackers can gain read access to the /etc/gshadow file, they can easily run a password cracking program against the hashed 
# password to break it. Other security information that is stored in the /etc/gshadow file (such as group administrators) could 
# also be useful to subvert the group.
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
#   class security_baseline::rules::debian::sec_gshadow_perms {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::debian::sec_gshadow_perms (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    file { '/etc/gshadow':
      ensure => present,
      owner  => 'root',
      group  => 'shadow',
      mode   => '0640',
    }
  } else {
    if ($facts['security_baseline']['file_permissions']['gshadow']['combined'] != '0-0-0') {
      echo { 'gshadow_perms':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
