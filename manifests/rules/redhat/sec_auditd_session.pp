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
# @param level
#    Profile level
#
# @param scored
#    Indicates if a rule is scored or not
#
# @example
#   class { 'security_baseline::rules::redhat::sec_auditd_session':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline::rules::redhat::sec_auditd_session (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    file_line { 'watch session rule 1':
      content => '-w /var/run/utmp -p wa -k session',
    }
  } else {
    if($facts['security_baseline']['auditd']['session'] == false) {
      echo { 'auditd-session':
        message  => 'Auditd has no rule to collect session initiation events.',
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
