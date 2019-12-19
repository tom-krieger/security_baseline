# @summary 
#    Ensure login and logout events are collected (Scored)
#
# Monitor login and logout events. The parameters below track changes to files associated with login/logout events. 
# The file /var/log/lastlog maintain records of the last time a user successfully logged in. The /var/run/failock 
# directory maintains records of login failures via the pam_faillock module.
# 
# Rationale:
# Monitoring login/logout events could provide a system administrator with information associated with brute force 
# attacks against user logins.
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
#   class { 'security_baseline::rules::common::sec_auditd_logins':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline::rules::common::sec_auditd_logins (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    file_line { 'logins policy rule 1':
      ensure => present,
      path   => $security_baseline::auditd_rules_file,
      line   => '-w /var/log/lastlog -p wa -k logins',
      notify => Exec['reload auditd rules'],
    }
    file_line { 'logins policy rule 2':
      ensure => present,
      path   => $security_baseline::auditd_rules_file,
      line   => '-w /var/run/faillock/ -p wa -k logins',
      notify => Exec['reload auditd rules'],
    }
  } else {
    if($facts['security_baseline']['auditd']['logins'] == false) {
      echo { 'auditd-logins':
        message  => 'Auditd has no rule to collect login and logout events.',
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
