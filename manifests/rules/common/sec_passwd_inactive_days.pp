# @summary 
#    Ensure inactive password lock is 30 days or less (Scored)
#
# User accounts that have been inactive for over a given period of time can be automatically disabled. 
# It is recommended that accounts that are inactive for 30 days after password expiration be disabled.
# 
# Rationale:
# Inactive accounts pose a threat to system security since the users are not logging in to notice failed 
# login attempts or other anomalies.
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
# @param inactive_pass_days
#    Days after an inactive account is locked
#
# @example
#   class security_baseline::rules::common::sec_passwd_inactive_days {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::common::sec_passwd_inactive_days (
  Boolean $enforce            = true,
  String $message             = '',
  String $log_level           = '',
  Integer $inactive_pass_days = 30,
) {
  if($enforce) {
    $facts['security_baseline']['local_users'].each |String $user, Hash $attributes| {
      if (
        ($attributes['password_expires_days'] != 'never') and
        ($attributes['password_expires_days'] != 'password must be changed') and
        ($attributes['password_inactive_days'] != $inactive_pass_days)
      ) {
        exec { "chage --inactive ${inactive_pass_days} ${user}":
          path => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
        }
      }
    }

    if($facts['security_baseline']['pw_data']['inactive'] != $inactive_pass_days) {
      exec { "useradd -D -f ${inactive_pass_days}":
        path => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      }
    }
  } else {
    if($facts['security_baseline']['pw_data']['inactive_status']) {
      echo { 'pass-warn-days':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
