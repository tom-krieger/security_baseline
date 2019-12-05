# @summary 
#    Ensure separate partition exists for /var/log (Scored)
#
# The /var/log directory is used by system services to store log data.
#
# Rationale:
# There are two important reasons to ensure that system logs are stored on a separate partition: 
# protection against resource exhaustion (since logs can grow quite large) and protection of audit data.
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
#   class security_baseline::rules::common::sec_var_log_partition {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_var_log_partition (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {

  if($enforce) {
    if (has_key($facts, 'security_baseline')) and
      defined($facts['security_baseline']['partitions']['var_log']['partition']) and
      ($facts['security_baseline']['partitions']['var_log']['partition'] == undef) {
      echo { 'var-log-partition':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }

}
