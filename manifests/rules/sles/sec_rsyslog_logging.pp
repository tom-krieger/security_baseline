# @summary 
#    Ensure logging is configured (Not Scored)
#
# The /etc/rsyslog.conf and /etc/rsyslog.d/*.conf files specifies rules for logging and which files are to be used to 
# log certain classes of messages.
# 
# Rationale:
# A great deal of important security-related information is sent via rsyslog (e.g., successful and failed su attempts, f
# ailed login attempts, root login attempts, etc.).
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
# @param log_config
#    Logfiles to configure
#
# @example
#   class security_baseline::rules::sles::sec_rsyslog_logging {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#       log_config => {
#         '*.emerg' => ':omusrmsg:*',
#       }
#   }
#
# @api private
class security_baseline::rules::sles::sec_rsyslog_logging (
  Boolean $enforce   = true,
  String $message    = '',
  String $log_level  = '',
  Hash $log_config   = {},
) {
  if($enforce) {
    if(!defined(Package['rsyslog'])) {
      package { 'rsyslog':
        ensure => installed,
      }
      package { 'syslog-ng':
        ensure => absent,
      }
    }
    $log_config.each | $config, $data | {
      $src = $data['src']
      $dst = $data['dst']
      file { "/etc/rsyslog.d/${config}.conf":
        ensure  => present,
        content => "${src} ${dst}",
        notify  => Exec['reload-rsyslog'],
        require => Package['rsyslog'],
      }
    }
  }
}
