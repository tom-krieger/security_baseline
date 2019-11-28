# @summary 
#    Ensure at/cron is restricted to authorized users (Scored)
#
# Configure /etc/cron.allow and /etc/at.allow to allow specific users to use these services. If /etc/cron.allow 
# or /etc/at.allow do not exist, then /etc/at.deny and /etc/cron.deny are checked. Any user not specifically 
# defined in those files is allowed to use at and cron. By removing the files, only users in /etc/cron.allow 
# and /etc/at.allow are allowed to use at and cron. Note that even though a given user is not listed in cron.allow , 
# cron jobs can still be run as that user. The cron.allow file only controls administrative access to the crontab 
# command for scheduling and modifying cron jobs.
#
# Rationale:
# On many systems, only the system administrator is authorized to schedule cron jobs. Using the cron.allow file to 
# control who can run cron jobs enforces this policy. It is easier to manage an allow list than a deny list. In a 
# deny list, you could potentially add a user ID to the system and forget to add it to the deny files.
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
#   class security_baseline::rules::redhat::sec_cron_restrict {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_cron_restrict (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {

    file { '/etc/cron.allow':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
    }

    file { '/etc/cron.deny':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
    }

    file { '/etc/at.allow':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
    }

    file { '/etc/at.deny':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
    }

  } else {

    if($facts['security_baseline']['cron']['restrict'] == false) {
      echo { 'cron-restrict':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
