# @summary 
#     Ensure rsyslog Service is enabled (Scored)
#
# Once the rsyslog package is installed it needs to be activated.
#
# Rationale:
# If the rsyslog service is not activated the system may default to the syslogd service or lack logging instead.
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
#   class security_security_baseline::rules::redhat::sec_rsyslog_service {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_rsyslog_service (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    if(!defined(Package['rsyslog'])) {

      ensure_packages(['rsyslog'], {
        ensure => installed,
      })

      ensure_packages(['syslog-ng'], {
        ensure => absent,
      })
    }
    if(!defined(Service['rsyslog'])) {

      ensure_resource('service', ['rsyslog'], {
        ensure  => running,
        enable  => true,
        require => Package['rsyslog'],
      })

    }
  } else {
    if($facts['security_baseline']['syslog']['rsyslog']['service'] != 'enabled') {
      echo { 'rsyslog-service':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
