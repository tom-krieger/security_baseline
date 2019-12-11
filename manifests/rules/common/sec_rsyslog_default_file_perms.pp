# @summary 
#    Ensure rsyslog default file permissions configured (Scored)
#
# rsyslog will create logfiles that do not already exist on the system. This setting controls what permissions 
# will be applied to these newly created files.
#
# Rationale:
# It is important to ensure that log files have the correct permissions to ensure that sensitive data is 
# archived and protected.
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
#   class security_baseline::rules::common::sec_rsyslog_default_file_perms {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_rsyslog_default_file_perms (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    @package { 'rsyslog':
      ensure => installed,
    }
    @package { 'syslog-ng':
      ensure => absent,
    }
    file_line { 'rsyslog-filepermissions':
      ensure  => present,
      path    => '/etc/rsyslog.conf',
      line    => '$FileCreateMode 0640',
      match   => '^\$FileCreateMode.*',
      notify  => Exec['reload-rsyslog'],
      require => Package['rsyslog'],
    }
    if(!defined(File['/etc/rsyslog.d/'])) {
      file { '/etc/rsyslog.d/':
        ensure  => directory,
        recurse => true,
        mode    => '0640',
        require => Package['rsyslog'],
      }
    }
  } else {
    if($facts['security_baseline']['syslog']['rsyslog']['filepermissions'] != '0640') {
      echo { 'rsyslog-file-permissions':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
