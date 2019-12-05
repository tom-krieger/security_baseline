# @summary 
#    Ensure remote syslog-ng messages are only accepted on designated log hosts (Not Scored)
#
# By default, syslog-ng does not listen for log messages coming in from remote systems. 
#
# Rationale:
# The guidance in the section ensures that remote log hosts are configured to only accept syslog-ng data from 
# hosts within the specified domain and that those systems that are not designed to be log hosts do not accept 
# any remote syslog-ng messages. This provides protection from spoofed log data and ensures that system administrators 
# are reviewing reasonably complete syslog data in a central location.
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
# @param is_loghost
#    Flag if host is a remote log destination for rsyslog
#
# @example
#   class security_baseline::rules::common::sec_syslogng_remote_syslog {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#       is_loghost => false,
#   }
#
# @api private
class security_baseline::rules::common::sec_syslogng_remote_syslog (
  Boolean $enforce    = true,
  String $message     = '',
  String $log_level   = '',
  Boolean $is_loghost = false,
) {
  if($enforce) {
    if $is_loghost {
      file_line { 'syslog-ng remote 1':
        ensure => present,
        path   => '/etc/syslog-ng/syslog-ng.conf',
        line   => 'source net{ tcp(); };',
        match  => '^source net',
        notify => Exec['reload-syslog-ng'],
      }

      file_line { 'syslog-ng remote 2':
        ensure => present,
        path   => '/etc/syslog-ng/syslog-ng.conf',
        line   => 'destination remote { file("/var/log/remote/${FULLHOST}-log"); };', # lint:ignore:single_quote_string_with_variables
        match  => '^destination remote',
        notify => Exec['reload-syslog-ng'],
      }

      file_line { 'syslog-ng remote 3':
        ensure => present,
        path   => '/etc/syslog-ng/syslog-ng.conf',
        line   => 'log { source(net); destination(remote); };',
        notify => Exec['reload-syslog-ng'],
      }
    } else {
      file_line { 'syslog-ng remote 1':
        ensure => present,
        path   => '/etc/syslog-ng/syslog-ng.conf',
        line   => '',
        match  => '^source net',
        notify => Exec['reload-syslog-ng'],
      }

      file_line { 'syslog-ng remote 2':
        ensure => present,
        path   => '/etc/syslog-ng/syslog-ng.conf',
        line   => '',
        match  => '^destination remote',
        notify => Exec['reload-syslog-ng'],
      }
    }
  } else {
    if(
      ($facts['security_baseline']['syslog']['syslog-ng']['loghost'] == false) and ($is_loghost) or
      ($facts['security_baseline']['syslog']['syslog-ng']['loghost'] == true) and ($is_loghost == false)
    ) {
      echo { 'syslogng-service':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
