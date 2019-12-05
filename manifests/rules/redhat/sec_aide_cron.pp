# @summary 
#    Ensure filesystem integrity is regularly checked (Scored)
#
# Periodic checking of the filesystem integrity is needed to detect changes to the filesystem.
#
# Rationale:
# Periodic file checking allows the system administrator to determine on a regular basis if critical 
# files have been changed in an unauthorized fashion.
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
#   class security_baseline::rules::redhat::sec_aide_cron {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_aide_cron (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    if(
      ($facts['security_baseline']['aide']['version'] != 'none') and
      ($facts['security_baseline']['aide']['status'] == 'installed')
    ) {

      file { '/etc/cron.d/aide.cron':
        ensure  => file,
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
        content => '0 5 * * * root /usr/sbin/aide --check',
      }

    }

  } else {

    if(empty($facts['security_baseline']['aide']['cron'])) {

      echo { 'aide-cron':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
