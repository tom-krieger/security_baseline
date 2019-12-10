# @summary 
#    Ensure logging is configured (Not Scored)
#
# The /etc/syslog-ng/syslog-ng.conf file specifies rules for logging and which files are to be used 
# to log certain classes of messages.
#
# Rationale:
# A great deal of important security-related information is sent via syslog-ng (e.g., successful and 
# failed su attempts, failed login attempts, root login attempts, etc.).
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
# @param log_config
#    Logfile configuration
#
# @example
#   class security_baseline::rules::common::sec_syslogng_service {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#       log_config => ['...', '...']
#   }
#
# @api private
class security_baseline::rules::common::sec_syslogng_logging (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
  Array $log_config = [],
) {
  if($enforce) {
    $log_config.each | $config | {
      file_line { "syslog-ng logs ${config}":
        ensure => present,
        path   => '/etc/syslog-ng/syslog-ng.conf',
        line   => $config,
        notify => Exec['reload-syslog-ng'],
      }
    }
  }
}
