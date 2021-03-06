# @summary 
#    Ensure session initiation information is collected (Scored)
#
# Monitor session initiation events. The parameters in this section track changes to the files 
# associated with session events. The file /var/run/utmp file tracks all currently logged in users. 
# All audit records will be tagged with the identifier "session." The /var/log/wtmp file tracks 
# logins, logouts, shutdown, and reboot events. The file /var/log/btmp keeps track of failed login 
# attempts and can be read by entering the command /usr/bin/last -f /var/log/btmp . All audit records 
# will be tagged with the identifier "logins."
#
# Rationale:
# Monitoring these files for changes could alert a system administrator to logins occurring at unusual 
# hours, which could indicate intruder activity (i.e. a user logging in at a time when they do not normally 
# log in).
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
#   class { 'security_baseline::rules::common::sec_auditd_session_logins':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline::rules::common::sec_auditd_session_logins (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    file_line { 'watch session rule 2':
      ensure => present,
      path   => $security_baseline::auditd_rules_file,
      line   => '-w /var/log/wtmp -p wa -k logins',
      notify => Exec['reload auditd rules'],
    }
    file_line { 'watch session rule 3':
      ensure => present,
      path   => $security_baseline::auditd_rules_file,
      line   => '-w /var/log/btmp -p wa -k logins',
      notify => Exec['reload auditd rules'],
    }
  } else {
    if($facts['security_baseline']['auditd']['session-logins'] == false) {
      echo { 'auditd-session-logins':
        message  => 'Auditd has no rule to collect session initiation events (logins)',
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
