# @summary 
#    Ensure unsuccessful unauthorized file access attempts are collected (Scored)
#
# Monitor for unsuccessful attempts to access files. The parameters below are associated with 
# system calls that control creation ( creat ), opening ( open , openat ) and truncation 
# ( truncate , ftruncate ) of files. An audit log record will only be written if the user is a 
# non- privileged user (auid > = 1000), is not a Daemon event (auid=4294967295) and if the 
# system call returned EACCES (permission denied to the file) or EPERM (some other permanent 
# error associated with the specific system call). All audit records will be tagged with the 
# identifier "access."
#
# Rationale:
# Failed attempts to open, create or truncate files could be an indication that an individual 
# or process is trying to gain unauthorized access to the system.
#
# @param enforce
#    Enforce the rule or just test and log
#
# @param message
#    Message to print into the log
#
# @param log_level
#    The log_level for the above message
#
# @example
#   class security_baseline::rules::redhat::sec_aauditd_access {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::redhat::sec_auditd_access (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    file_line { 'watch access rule 1':
      ensure => present,
      path   => $secutity_baseline::auditd_rules_file,
      line   => '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access', #lint:ignore:140chars
    }
    file_line { 'watch access rule 2':
      ensure => present,
      path   => $secutity_baseline::auditd_rules_file,
      line   => '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access', #lint:ignore:140chars
    }
    if($facts['architecture'] == 'x86_64') {
      file_line { 'watch access rule 3':
        ensure => present,
        path   => $secutity_baseline::auditd_rules_file,
        line   => '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access', #lint:ignore:140chars
      }
      file_line { 'watch access rule 4':
        ensure => present,
        path   => $secutity_baseline::auditd_rules_file,
        line   => '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access', #lint:ignore:140chars
      }
    }
  } else {
    if($facts['security_baseline']['auditd']['access'] == false) {
      echo { 'auditd-access':
        message  => 'Auditd has no rule to collect unsuccessful unauthorized file access attempts.',
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
