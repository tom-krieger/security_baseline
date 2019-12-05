# @summary 
#    Ensure bootloader password is set (Scored)
#
# Setting the boot loader password will require that anyone rebooting the system must enter a password 
# before being able to set command line boot parameters
#
# Rationale:
# Requiring a boot password upon execution of the boot loader will prevent an unauthorized user from 
# entering boot parameters or changing the boot partition. This prevents users from weakening security 
# (e.g. turning off SELinux at boot time).
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
#   class security_baseline::rules::common::sec_grub_passwd {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_grub_passwd (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    if($facts['security_baseline']['grub']['grub_passwd'] == false) {

      echo { 'grub-passwd':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }

    }
  }
}
