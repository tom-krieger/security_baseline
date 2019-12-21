# @summary 
#    Ensure journald is configured to write logfiles to persistent disk (Scored)
#
# Data from journald may be stored in volatile memory or persisted locally on the server. Logs 
# in memory will be lost upon a system reboot. By persisting logs to local disk on the server 
# they are protected from loss.
#
# Rationale:
# Writing log data to disk will provide the ability to forensically reconstruct events which may 
# have impacted the operations or security of a system even after a system crash or reboot.
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
#   class security_baseline::rules::common::sec_journald_persistent_disk {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_journald_persistent_disk (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if ($enforce) {
    file_line { 'write to persistent disk':
      path  => '/etc/systemd/journald.conf',
      match => 'Storage=',
      line  => 'Storage=persistent',
    }
  } else {
    if (
      ($facts['security_baseline']['journald']['storage_persistent'] == 'none') or
      ($facts['security_baseline']['journald']['storage_persistent'] == 'no')
    ) {
      echo { 'journald-storage-persistent':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
