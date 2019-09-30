# @summary 
#    Ensure permissions on /etc/cron.d are configured (Scored)
#
# The /etc/cron.d directory contains system cron jobs that need to run in a similar manner to the hourly, 
# daily weekly and monthly jobs from /etc/crontab , but require more granular control as to when they run. 
# The files in this directory cannot be manipulated by the crontab command, but are instead edited by system 
# administrators using a text editor. The commands below restrict read/write and search access to user and 
# group root, preventing regular users from accessing this directory.
# 
# Rationale:
# Granting write access to this directory for non-privileged users could provide them the means for gaining 
# unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user 
# insight in how to gain elevated privileges or circumvent auditing controls.
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
#   class security_baseline::rules::sec_stc_crond {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_etc_crond (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {

    file { '/etc/cron.d':
      ensure => directory,
      owner  => 'root',
      group  => 'root',
      mode   => '0700',
      }

  } else {

    if(
      ($facts['security_baseline']['cron']['/etc/cron.d']['uid'] != 0) or
      ($facts['security_baseline']['cron']['/etc/cron.d']['gid'] != 0) or
      ($facts['security_baseline']['cron']['/etc/cron.d']['mode'] != 0700)
    ) {
      echo { 'etc-cron-d':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
