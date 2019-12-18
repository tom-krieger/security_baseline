# @summary 
#    Ensure nodev option set on /var/tmp partition (Scored)
#
# The nodev mount option specifies that the filesystem cannot contain special devices.
#
# Rationale:
# Since the /var/tmp filesystem is not intended to support devices, set this option to ensure that 
# users cannot attempt to create block or character special devices in /var/tmp .
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
#   class security_baseline::rules::common::sec_var_tmp_nodev {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_var_tmp_nodev (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if ($enforce) {
    security_baseline::set_mount_options { '/var/tmp-nodev':
      mountpoint => '/var/tmp',
      mountoptions => 'nodeb',
    }
  } else {
    if (has_key($facts, 'security_baseline')) {
      if $facts['security_baseline']['partitions']['var_tmp']['nodev'] == false {
        echo { 'var-tmp-nodev':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
    }
  }
}
