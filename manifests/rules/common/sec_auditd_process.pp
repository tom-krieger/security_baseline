# @summary 
#    Ensure auditing for processes that start prior to auditd is enabled (Scored)
#
# Configure grub so that processes that are capable of being audited can be audited even if they start up 
# prior to auditd startup.
#
# Rationale:
# Audit events need to be captured on processes that start up prior to auditd, so that potential malicious 
# activity cannot go undetected.
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
# @example
#   class { 'security_baseline::rules::common::sec_auditd_process':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline::rules::common::sec_auditd_process (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    kernel_parameter { 'audit=1':
      ensure => present,
    }
  } else {
    if($facts['security_baseline']['auditd']['auditing_process'] == 'none') {
      echo { 'auditd-process':
        message  => 'Auditd process not configured in grub.',
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
