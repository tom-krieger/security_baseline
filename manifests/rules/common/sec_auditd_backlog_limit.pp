# @summary 
#    Ensure audit_backlog_limit is sufficient (Scored)
#
# The backlog limit has a default setting of 64
#
# Rationale:
# during boot if audit=1, then the backlog will hold 64 records. If more that 64 records are 
# created during boot, auditd records will be lost and potential malicious activity could go 
# undetected.
#
# @param enforce
#    Sets rule enforcemt. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @param message
#    Message to print into the log
#
# @param log_level
#    Loglevel for the message
#
# @param backlog_limit
#    Number of records in backlog
#
# @example
#   class { 'security_baseline::rules::common::sec_auditd_backlog_limit':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#             backlog_limit => 8192,
#   }
#
# @api private
class security_baseline::rules::common::sec_auditd_backlog_limit (
  Boolean $enforce       = true,
  String $message        = '',
  String $log_level      = '',
  Integer $backlog_limit = 8192,
) {
  if ($enforce) {
    kernel_parameter { "audit_backlog_limit=${backlog_limit}":
      ensure => present,
    }
  } else {
    if($facts['security_baseline']['auditd']['backlog_limit'] == 'none') {
      echo { 'auditd-backlog-limit':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
