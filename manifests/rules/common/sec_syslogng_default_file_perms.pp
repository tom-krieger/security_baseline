# @summary 
#    Ensure syslog-ng default file permissions configured (Scored)
#
# syslog-ng will create logfiles that do not already exist on the system. This setting controls what 
# permissions will be applied to these newly created files.
#
# Rationale:
# It is important to ensure that log files exist and have the correct permissions to ensure that sensitive 
# syslog-ng data is archived and protected.
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
#   class security_baseline::rules::common::sec_syslogng_default_file_perms {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_syslogng_default_file_perms (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    if(!defined(Package['syslog-ng'])) {
      package { 'syslog-ng':
        ensure => installed,
      }
      package { 'rsyslog':
        ensure => absent,
      }
    }
    file_line { 'syslog-ng permissions':
      ensure  => present,
      path    => '/etc/syslog-ng/syslog-ng.conf',
      line    => 'options { flush_lines (0); time_reopen (10); log_fifo_size (1000); chain_hostnames(off); flush_lines(0); perm(0640); stats_freq(3600); threaded(yes); use_dns (no); use_fqdn (no); create_dirs (yes); keep_hostname (yes);};', #lint:ignore:140chars
      notify  => Exec['reload-syslog-ng'],
      require => Package['syslog-ng'],
    }
  } else {
    if($facts['security_baseline']['syslog']['syslog-ng']['filepermissions'] != '0640') {
      echo { 'syslogng-file-permissions':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
