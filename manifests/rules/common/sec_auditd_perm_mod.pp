# @summary 
#    Ensure discretionary access control permission modification events are collected (Scored)
#
# Monitor changes to file permissions, attributes, ownership and group. The parameters in this section track 
# changes for system calls that affect file permissions and attributes. The chmod , fchmod and fchmodat system 
# calls affect the permissions associated with a file. The chown , fchown , fchownat and lchown system calls 
# affect owner and group attributes on a file. The setxattr , lsetxattr , fsetxattr (set extended file attributes) 
# and removexattr , lremovexattr , fremovexattr (remove extended file attributes) control extended file attributes. 
# In all cases, an audit record will only be written for non-system user ids (auid >= 1000) and will ignore Daemon 
# events (auid = 4294967295). All audit records will be tagged with the identifier "perm_mod."
#
# Rationale:
# Monitoring for changes in file attributes could alert a system administrator to activity that could indicate 
# intruder activity or policy violation.
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
#   class { 'security_baseline::rules::common::sec_auditd_perm_mod':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline::rules::common::sec_auditd_perm_mod (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    file_line { 'watch perm mod rule 1':
      ensure => present,
      path   => $security_baseline::auditd_rules_file,
      line   => '-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod',
      notify => Exec['reload auditd rules'],
    }
    file_line { 'watch perm mod rule 2':
      ensure => present,
      path   => $security_baseline::auditd_rules_file,
      line   => '-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod',
      notify => Exec['reload auditd rules'],
    }
    file_line { 'watch perm mod rule 3':
      ensure => present,
      path   => $security_baseline::auditd_rules_file,
      line   => '-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod', #lint:ignore:140chars
      notify => Exec['reload auditd rules'],
    }
    if($facts['architecture'] == 'x86_64') {
      file_line { 'watch perm mod rule 4':
        ensure => present,
        path   => $security_baseline::auditd_rules_file,
        line   => '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod',
        notify => Exec['reload auditd rules'],
      }
      file_line { 'watch perm mod rule 5':
        ensure => present,
        path   => $security_baseline::auditd_rules_file,
        line   => '-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod',
        notify => Exec['reload auditd rules'],
      }
      file_line { 'watch perm mod rule 6':
        ensure => present,
        path   => $security_baseline::auditd_rules_file,
        line   => '-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod', #lint:ignore:140chars
        notify => Exec['reload auditd rules'],
      }
    }
  } else {
    if($facts['security_baseline']['auditd']['perm-mod'] == false) {
      echo { 'auditd-perm-mod':
        message  => 'Auditd has no rule to collect discretionary access control permission modification events.',
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
