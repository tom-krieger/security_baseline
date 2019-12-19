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
# @param attempts
#    Lock account after this number of failed logins
#
# @param lockouttime
#    Lockout the account for this number of seconds
#
# @example
#   class security_baseline::rules::redhat::sec_pam_lockout {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_pam_lockout (
  Boolean $enforce     = true,
  String $message      = '',
  String $log_level    = '',
  Integer $attempts    = 3,
  Integer $lockouttime = 900,
) {
  $services = [
    'system-auth',
    'password-auth',
  ]

  if($enforce) {

    $services.each | $service | {

      pam { "pam_unix ${service}":
        ensure           => present,
        service          => $service,
        type             => 'auth',
        module           => 'pam_unix.so',
        control          => '[success=1 default=bad]',
        control_is_param => true,
        arguments        => [],
      }

      pam { "pam_faillock preauth ${service}":
        ensure           => present,
        service          => $service,
        type             => 'auth',
        module           => 'pam_faillock.so',
        control          => 'required',
        control_is_param => true,
        arguments        => [
          'preauth',
          'audit',
          'silent',
          "deny=${attempts}",
          "unlock_time=${lockouttime}",
        ],
        position         => 'before *[type="auth" and module="pam_unix.so"]',
      }

      pam { "pam_faillock authfail ${service}":
        ensure           => present,
        service          => $service,
        type             => 'auth',
        module           => 'pam_faillock.so',
        control          => '[default=die]',
        control_is_param => true,
        arguments        => [
          'authfail',
          'audit',
          "deny=${attempts}",
          "unlock_time=${lockouttime}",
        ],
        position         => 'after *[type="auth" and module="pam_unix.so"]',
      }

      pam { "pam_faillock authsucc ${service}":
        ensure           => present,
        service          => $service,
        type             => 'auth',
        module           => 'pam_faillock.so',
        control          => 'sufficient',
        control_is_param => true,
        arguments        => [
          'authsucc',
          'audit',
          "deny=${attempts}",
          "unlock_time=${lockouttime}",
        ],
        position         => 'after *[type="auth" and module="pam_faillock.so" and control="[default=die]"]',
      }
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
