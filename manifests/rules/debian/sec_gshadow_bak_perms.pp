# @summary 
#    Ensure permissions on /etc/gshadow- are configured (Scored)
#
# The /etc/gshadow- file is used to store backup information about groups that is critical to the security of those accounts, 
# such as the hashed password and other security information.
#
# Rationale:
# It is critical to ensure that the /etc/gshadow- file is protected from unauthorized access. Although it is protected by default, 
# the file permissions could be changed either inadvertently or through malicious actions.
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
#   class security_baseline::rules::debian::sec_gshadow_bak_perms {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::debian::sec_gshadow_bak_perms (
  $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {
    file { '/etc/gshadow-':
      ensure => present,
      owner  => 'root',
      group  => 'shadow',
      mode   => '0640',
    }
  } else {
    if ($facts['security_baseline']['file_permissions']['gshadow-']['combined'] != '0-0-0') {
      echo { 'gshadow_bak_perms':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
