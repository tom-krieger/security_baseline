# @summary 
#    Ensure audit log storage size is configured (Not Scored)
#
# Configure the maximum size of the audit log file. Once the log reaches the maximum size, it will be 
# rotated and a new log file will be started.
#
# Rationale:
# It is important that an appropriate size is determined for log files so that they do not impact the 
# system and audit data is not lost.
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
# @param max_log_file
#    Maximal log file size, defaults to 26 MB
#
# @example
#   class { 'security_baseline::rules::common::sec_auditd_max_log_file':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#             max_log_size => 32,
#   }
#
# @api private
class security_baseline::rules::common::sec_auditd_max_log_file (
  Boolean $enforce      = true,
  String $message       = '',
  String $log_level     = '',
  Integer $max_log_size = 16,
) {
  if($enforce) {
    file_line { 'auditd_max_log_size':
      path  => '/etc/audit/auditd.conf',
      line  => "max_log_file = ${max_log_size}",
      match => '^max_log_file =',
    }
  } else {
    if($facts['security_baseline']['auditd']['max_log_file'] == 'none') {
      echo { 'auditd-max-log-size':
        message  => 'Auditd setting for max_log_file is not correct.',
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
