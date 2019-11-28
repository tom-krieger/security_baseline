# @summary 
#    Ensure separate partition exists for /var/log/audit (Scored)
#
# The auditing daemon, auditd , stores log data in the /var/log/audit directory. 
#
# Rationale:
# There are two important reasons to ensure that data gathered by auditd is stored on a separate partition: 
# protection against resource exhaustion (since the audit.log file can grow quite large) and protection of audit 
# data. The audit daemon calculates how much free space is left and performs actions based on the results. If 
# other processes (such as syslog ) consume space in the same partition as auditd , it may not perform as desired.
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
#   class security_baseline::rules::sec_var_log_audit_partition {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_var_log_audit_partition (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {

  if($enforce) {
    if (has_key($facts, 'security_baseline')) ancd
      defined($facts['security_baseline']['partitions']['var_log_audit']['partition']) and
      ($facts['security_baseline']['partitions']['var_log_audit']['partition'] == undef) {

      echo { 'var-log-audit-partition':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
        }
      }
  }

}
