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
# @example
#   class security_baseline::special_rules::ssec_pam_pw_requirements {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::special_rules::sec_pam_old_passwords (
  Boolean $enforce            = true,
  String $message             = '',
  String $log_level           = '',
  String $logfile             = '',
  Integer $oldpasswords       = 5,
) {
  $services = [
    'system-auth',
    'password-auth',
  ]

  if($enforce) {

    $services.each | $service | {

      pam { "pam ${service} sufficient":
        ensure    => present,
        service   => $service,
        type      => 'password',
        control   => 'sufficient',
        module    => 'pam_unix.so',
        arguments => ["remember=${oldpasswords}", 'shadow', 'try_first_pass', 'use_authtok'],
        position  => 'after *[type="password" and module="pam_unix.so" and control="requisite"]',
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
