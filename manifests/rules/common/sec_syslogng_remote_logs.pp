# @summary 
#    Ensure syslog-ng is configured to send logs to a remote log host (Not Scored)
#
# The syslog-ng utility supports the ability to send logs it gathers to a remote log host or to 
# receive messages from remote hosts, reducing administrative overhead.
#
# Rationale:
# Storing log data on a remote host protects log integrity from local attacks. If an attacker gains root access 
# on the local system, they could tamper with or remove log data that is stored on the local system
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
# @param remote_log_host
#    Remote syslog server to send logs to
#
# @example
#   class ssecurity_baseline::rules::redhat::sec_syslogng_remote_logs {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#       remote_log_host => '10.10.54.2',
#   }
#
# @api private
class security_baseline::rules::common::sec_syslogng_remote_logs (
  Boolean $enforce        = true,
  String $message         = '',
  String $log_level       = '',
  String $remote_log_host = '',
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
    if($remote_log_host != '') {
      file_line { 'syslog-ng remote_log_host':
        ensure  => present,
        path    => '/etc/syslog-ng/syslog-ng.conf',
        line    => "destination logserver { tcp(\"${remote_log_host}\" port(514)); }; log { source(src); destination(logserver); };",
        match   => '^destination logserver',
        notify  => Exec['reload-syslog-ng'],
        require => Package['syslog-ng'],
      }
    }
  } else {
    if($facts['security_baseline']['syslog']['syslog-ng']['remotesyslog'] == 'none') {
      echo { 'syslogng-remote-log-host':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
