# @summary 
#    Ensure lockout for failed password attempts is configured (Scored)
#
# Lock out users after n unsuccessful consecutive login attempts. The first sets of changes are made to the PAM 
# configuration files. The second set of changes are applied to the program specific PAM configuration file. The 
# second set of changes must be applied to each program that will lock out users. Check the documentation for each 
# secondary program for instructions on how to configure them to work with PAM.
#
# Set the lockout number to the policy in effect at your site.
#
# Rationale:
# Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute force password attacks against 
# your systems.
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
# @param attemps
#    Lock account after this number of failed logins
#
# @param lockouttime
#    Lockout the account for this number of seconds
#
# @example
#   class security_baseline::rules::debian::sec_pam_lockout {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::debian::sec_pam_lockout (
  Boolean $enforce     = true,
  String $message      = '',
  String $log_level    = '',
  Integer $attempts    = 3,
  Integer $lockouttime = 900,
) {
  if($enforce) {
    pam { 'pam_tally2 auth common-auth':
      ensure    => present,
      service   => 'common-auth',
      type      => 'auth',
      module    => 'pam_tally2.so',
      control   => 'required',
      arguments => [
        'onerr=fail',
        'audit',
        'silent',
        "deny=${attempts}",
        "unlock_time=${lockouttime}",
      ],
    }
  } else {
    unless ($facts['security_baseline']['pam']['pwquality']['lockout']) {
      echo { 'pam-lockout':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
