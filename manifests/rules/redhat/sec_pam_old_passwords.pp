# @summary 
#    Ensure password reuse is limited (Scored)
#
# The /etc/security/opasswd file stores the users' old passwords and can be checked to ensure that users 
# are not recycling recent passwords.
#
# Rationale:
# Forcing users not to reuse their past 5 passwords make it less likely that an attacker will be able to 
# guess the password.
# 
# Note that these change only apply to accounts configured on the local system.
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
# @param oldpasswords
#    Number of old passwords to remember
#
# @param sha512
#    Enable or disable sha512 password encryption
#
# @example
#   class security_baseline::rules::redhat::ssec_pam_pw_requirements {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::redhat::sec_pam_old_passwords (
  Boolean $enforce            = true,
  String $message             = '',
  String $log_level           = '',
  Integer $oldpasswords       = 5,
  Boolean $sha512             = true,
) {
  $services = [
    'system-auth',
    'password-auth',
  ]

  if($enforce) {
    if ($facts['operatingsystemrelease'] > '7') {
      exec { 'update authselect config for old passwords':
        command => "/usr/share/security_baseline/bin/update_pam_pw_reuse_config.sh ${oldpasswords}",
        path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      }
    } else {
      if($sha512) {
        $arguments = ["remember=${oldpasswords}", 'shadow', 'sha512', 'try_first_pass', 'use_authtok']
      } else {
        $arguments = ["remember=${oldpasswords}", 'shadow', 'try_first_pass', 'use_authtok']
      }

      $services.each | $service | {

        pam { "pam-${service}-sufficient":
          ensure    => present,
          service   => $service,
          type      => 'password',
          control   => 'sufficient',
          module    => 'pam_unix.so',
          arguments => $arguments,
          position  => 'after *[type="password" and module="pam_unix.so" and control="requisite"]',
        }
      }
    }
  } else {
    unless ($facts['security_baseline']['pam']['opasswd']['status']) {
      echo { 'password-reuse':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
