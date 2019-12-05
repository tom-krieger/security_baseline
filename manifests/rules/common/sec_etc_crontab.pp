# @summary 
#    Ensure permissions on /etc/crontab are configured (Scored)
#
# The /etc/crontab file is used by cron to control its own jobs. The commands in this item make sure that root 
# is the user and group owner of the file and that only the owner can access the file.
# 
# Rationale:
# This file contains information on what system jobs are run by cron. Write access to these files could provide 
# unprivileged users with the ability to elevate their privileges. Read access to these files could provide users 
# with the ability to gain insight on system jobs that run on the system and could provide them a way to gain 
# unauthorized privileged access.
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
#   class security_baseline::rules::common::sec_etc_crontab {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_etc_crontab (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {

    file { '/etc/crontab':
      ensure => present,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
      }

  } else {

    if(
      ($facts['security_baseline']['cron']['/etc/crontab']['uid'] != 0) or
      ($facts['security_baseline']['cron']['/etc/crontab']['gid'] != 0) or
      ($facts['security_baseline']['cron']['/etc/crontab']['mode'] != 0600)
    ) {
      echo { 'etc-crontab':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
