# @summary 
#    Ensure rsyslog is configured to send logs to a remote log host (Scored)
#
# The rsyslog utility supports the ability to send logs it gathers to a remote log host running syslogd(8) or 
# to receive messages from remote hosts, reducing administrative overhead.
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
#   class security_baseline::rules::debian::sec_rsyslog_remote_logs {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#       remote_log_host => '10.10.54.2',
#   }
#
# @api private
class security_baseline::rules::debian::sec_rsyslog_remote_logs (
  Boolean $enforce        = true,
  String $message         = '',
  String $log_level       = '',
  String $remote_log_host = '',
) {
  if($enforce) {
    if(!defined(Package['rsyslog'])) {
      Package { 'rsyslog':
        ensure => installed,
      }
      Package { 'syslog-ng':
        ensure => absent,
      }
    }
    if ($remote_log_host != '') {
      file_line { 'rsyslog-remote-log-host':
        ensure  => present,
        path    => '/etc/rsyslog.conf',
        line    => "*.* @@${remote_log_host}",
        match   => '^\*\.\* \@\@.*',
        notify  => Exec['reload-rsyslogd'],
        require => Package['rsyslog'],
      }
    }
  } else {
    if($facts['security_baseline']['syslog']['rsyslog']['remotesyslog'] == 'none') {
      echo { 'rsyslog-remote-log-host':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
