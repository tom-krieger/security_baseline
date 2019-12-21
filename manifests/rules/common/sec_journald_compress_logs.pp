# @summary 
#    Ensure journald is configured to compress large log files (Scored)
#
# The journald system includes the capability of compressing overly large files to avoid 
# filling up the system with logs or making the logs unmanageably large.
#
# Rationale:
# Uncompressed large files may unexpectedly fill a filesystem leading to resource unavailability. 
# Compressing logs prior to write can prevent sudden, unexpected filesystem impacts.
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
#   class security_baseline::rules::common::sec_journald_compress_logs {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_journald_compress_logs (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if ($enforce) {
    file_line { 'compress logs':
      path  => '/etc/systemd/journald.conf',
      match => 'Compress=',
      line  => 'Compress=yes',
    }
  } else {
    if (
      ($facts['security_baseline']['journald']['compress'] == 'none') or
      ($facts['security_baseline']['journald']['compress'] == 'no')
    ) {
      echo { 'journald-compress':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
