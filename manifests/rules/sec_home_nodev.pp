# @summary 
#    Ensure nodev option set on /home partition (Scored)
#
# The nodev mount option specifies that the filesystem cannot contain special devices.
#
# Rationale:
# Since the user partitions are not intended to support devices, set this option to ensure that users 
# cannot attempt to create block or character special devices.
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
#   class security_baseline::rules::sec_home_nodev {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_home_nodev (
  $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if $enforce {

    if $::home_partition {

      if $::home_nodev == false {
        echo { 'home-nodev':
          message   => $message,
          log_level => $log_level,
          withpath  => false,
        }
      }
    }
  }
}
