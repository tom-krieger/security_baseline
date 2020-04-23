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
#   class security_baseline::rules::debian::ssec_pam_pw_requirements {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::debian::sec_pam_old_passwords (
  Boolean $enforce      = true,
  String $message       = '',
  String $log_level     = '',
  Integer $oldpasswords = 5,
) {
  if($enforce) {
    Pam { 'pam-common-pw-history':
      ensure    => present,
      service   => 'common-password',
      type      => 'password',
      control   => 'required',
      module    => 'pam_pwhistory.so',
      arguments => ["remember=${oldpasswords}"],
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
