# @summary 
#    Ensure events that modify date and time information are collected (Scored)
#
# Capture events where the system date and/or time has been modified. The parameters in this section are set to 
# determine if the adjtimex (tune kernel clock), settimeofday (Set time, using timeval and timezone structures) 
# stime (using seconds since 1/1/1970) or clock_settime (allows for the setting of several internal clocks and 
# timers) system calls have been executed and always write an audit record to the /var/log/audit.log file upon 
# exit, tagging the records with the identifier "time-change"
#
# Rationale:
# Unexpected changes in system date and/or time could be a sign of malicious activity on the system.
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
#   class { 'security_baseline::rules::common::sec_auditd_time_change':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline::rules::common::sec_auditd_time_change (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    file_line { 'watch for date-time-change rule 1':
      ensure => present,
      path   => $security_baseline::auditd_rules_file,
      line   => '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change',
      notify => Exec['reload auditd rules'],
    }
    file_line { 'watch for date-time-change rule 2':
      ensure => present,
      path   => $security_baseline::auditd_rules_file,
      line   => '-a always,exit -F arch=b32 -S clock_settime -k time-change',
      notify => Exec['reload auditd rules'],
    }
    file_line { 'watch for date-time-change rule 3':
      ensure => present,
      path   => $security_baseline::auditd_rules_file,
      line   => '-w /etc/localtime -p wa -k time-change',
      notify => Exec['reload auditd rules'],
    }

    if($facts['architecture'] == 'x86_64') {
      file_line { 'watch for date-time-change rule 4':
        ensure => present,
        path   => $security_baseline::auditd_rules_file,
        line   => '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change',
        notify => Exec['reload auditd rules'],
      }
      file_line { 'watch for date-time-change rule 5':
        ensure => present,
        path   => $security_baseline::auditd_rules_file,
        line   => '-a always,exit -F arch=b64 -S clock_settime -k time-change',
        notify => Exec['reload auditd rules'],
      }
    }
  } else {
    if($facts['security_baseline']['auditd']['time-change'] == false) {
      echo { 'auditd-time-change':
        message  => 'Auditd has no rule to collect events changing date and time.',
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
