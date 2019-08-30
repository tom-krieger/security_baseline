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
# @param loglevel
#    The loglevel for the above message
#
# @example
#   class security_baseline::rules::sec_var_tmp_nodev {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_var_tmp_nodev (
  $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if $enforce {

    # Many of the options her5e could possibly be managed by a mount resource:
    # https://forge.puppet.com/puppetlabs/mount_core
    if $::var_tmp_partition {

      if $::var_tmp_nodev == false {
        notify { 'var-tmp-nodev':
          message  => $message,
          loglevel => $loglevel,
        }
      }
    }
  }
}
