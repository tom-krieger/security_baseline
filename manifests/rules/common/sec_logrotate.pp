# @summary 
#    Ensure logrotate is configured (Not Scored)
#
# The system includes the capability of rotating log files regularly to avoid filling up the 
# system with logs or making the logs unmanageable large. The file /etc/logrotate.d/syslog is 
# the configuration file used to rotate log files created by syslog or rsyslog.
#
# Rationale:
# By keeping the log files smaller and more manageable, a system administrator can easily archive these files 
# to another system and spend less time looking through inordinately large log files.
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
#   class security_baseline::rules::common::sec_logrotate {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_logrotate (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {
    class { '::logrotate':
      config => {
        dateext      => true,
        compress     => true,
        rotate       => 7,
        rotate_every => 'week',
        ifempty      => true,
      },
    }
  } else {
    if($facts['security_baseline']['packages_installed']['logrotate'] == false) {
      echo { 'logrotate':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
