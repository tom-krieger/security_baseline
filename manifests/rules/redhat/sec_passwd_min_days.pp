# @summary 
#    Ensure minimum days between password changes is 7 or more (Scored)
#
# The PASS_MIN_DAYS parameter in /etc/login.defs allows an administrator to prevent users from changing 
# their password until a minimum number of days have passed since the last time the user changed their 
# password. It is recommended that PASS_MIN_DAYS parameter be set to 7 or more days.
#
# Rationale:
# By restricting the frequency of password changes, an administrator can prevent users from repeatedly 
# changing their password in an attempt to circumvent password reuse controls.
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
# @param max_pass_days
#    Password expires after days
#
# @example
#   class security_baseline::rules::redhat::sec_passwd_min_days {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::redhat::sec_passwd_min_days (
  Boolean $enforce            = true,
  String $message             = '',
  String $log_level           = '',
  Integer $min_pass_days      = 7,
) {
  if($enforce) {
    file_line { 'password min days password change':
      ensure => present,
      path   => '/etc/login.defs',
      line   => "PASS_MIN_DAYS ${min_pass_days}",
      match  => '^#?PASS_MIN_DAYS',
    }

    $local_users = pick($facts['local_users'], {})

    $local_users.each |String $user, Hash $attributes| {
      if $attributes['password_expires_days'] != 'never' and $attributes['min_days_between_password_change'] != $min_pass_days {
        exec { "chage --mindays ${min_pass_days} ${user}":
          path => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
        }
      }
    }
  } else {
    if($facts['security_baseline']['pw_data']['pass_min_days_status']) {
      echo { 'pass-min-days':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
