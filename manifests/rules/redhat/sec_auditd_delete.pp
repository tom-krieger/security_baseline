# @summary 
#    Ensure file deletion events by users are collected (Scored)
#
# Monitor the use of system calls associated with the deletion or renaming of files and file 
# attributes. This configuration statement sets up monitoring for the unlink (remove a file), 
# unlinkat (remove a file attribute), rename (rename a file) and renameat (rename a file attribute) 
# system calls and tags them with the identifier "delete".
#
# Rationale:
# Monitoring these calls from non-privileged users could provide a system administrator with evidence 
# that inappropriate removal of files and file attributes associated with protected files is occurring. 
# While this audit option will look at all events, system administrators will want to look for specific 
# privileged files that are being deleted or altered.
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
#   class { 'security_baseline::rules::redhat::sec_auditd_delete':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline::rules::redhat::sec_auditd_delete (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if ($enforce) {
    file_line { 'watch deletes rule 1':
      ensure => present,
      path   => $security_baseline::auditd_rules_file,
      line   => '-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete',
      notify => Exec['reload auditd rules'],
    }
    if($facts['architecture'] == 'x86_64') {
      file_line { 'watch deletes rule 2':
        ensure => present,
        path   => $security_baseline::auditd_rules_file,
        line   => '-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete',
        notify => Exec['reload auditd rules'],
      }
    }
  } else {
    if($facts['security_baseline']['auditd']['delete'] == false) {
      echo { 'auditd-delete':
        message  => 'Auditd has no rule to collect file deletion events by users.',
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
