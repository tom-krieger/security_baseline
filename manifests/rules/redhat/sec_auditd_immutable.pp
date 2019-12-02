# @summary 
#    Ensure the audit configuration is immutable (Scored)
#
# Set system audit so that audit rules cannot be modified with auditctl . Setting the flag "-e 2" 
# forces audit to be put in immutable mode. Audit changes can only be made on system reboot.
#
# Rationale:
# In immutable mode, unauthorized users cannot execute changes to the audit system to potentially 
# hide malicious activity and then put the audit rules back. Users would most likely notice a 
# system reboot and that could alert administrators of an attempt to make unauthorized audit changes.
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
# @param level
#    Profile level
#
# @param scored
#    Indicates if a rule is scored or not
#
# @example
#   class { 'security_baseline::rules::redhat::sec_auditd_immutable':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline::rules::redhat::sec_auditd_immutable (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    file_line { '-e 2':
      ensure             => present,
      path               => $security_baseline::auditd_rules_file,
      line               => '-e 2',
      append_on_no_match => true,
      notify             => Exec['reload auditd rules'],
    }
  } else {
    if($facts['security_baseline']['auditd']['immutable'] == false) {
      echo { 'auditd-immutable':
        message  => 'Auditd configuration is not immutable.',
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
