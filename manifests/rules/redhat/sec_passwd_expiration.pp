# @summary 
#    Ensure password expiration is 365 days or less (Scored)
#
# The PASS_MAX_DAYS parameter in /etc/login.defs allows an administrator to force passwords to expire once they reach a defined age. 
# It is recommended that the PASS_MAX_DAYS parameter be set to less than or equal to 365 days.
#
# Rationale:
# The window of opportunity for an attacker to leverage compromised credentials or successfully compromise credentials via an online 
# brute force attack is limited by the age of the password. Therefore, reducing the maximum age of a password also reduces an 
# attacker's window of opportunity.
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
#   class security_baseline::rules::redhat::sec_passwd_expiration {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::redhat::sec_passwd_expiration (
  Boolean $enforce            = true,
  String $message             = '',
  String $log_level           = '',
  Integer $max_pass_days      = 90,
) {
  if($enforce) {
    file_line { 'password expiration policy':
      ensure => present,
      path   => '/etc/login.defs',
      line   => "PASS_MAX_DAYS ${max_pass_days}",
      match  => '^#?PASS_MAX_DAYS',
    }

    $local_users = pick($facts['local_users'], {})

    $local_users.each |String $user, Hash $attributes| {
      if $attributes['password_expires_days'] != 'never' and $attributes['max_days_between_password_change'] != $max_pass_days {
        exec { "chage --maxdays ${max_pass_days} ${user}":
          path => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
        }
      }
    }
  } else {
    if($facts['security_baseline']['pw_data']['pass_max_days_status']) {
      echo { 'pass-max-days':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
