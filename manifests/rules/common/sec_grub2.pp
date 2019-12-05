# @summary 
#    Ensure permissions on bootloader config are configured (Scored)
#
# The grub configuration file contains information on boot settings and passwords for unlocking boot 
# options. The grub configuration is usually located at /boot/grub2/grub.cfg and linked as /etc/grub2.cfg. 
# Additional settings can be found in the /boot/grub2/user.cfg file.
#
# Rationale:
# Setting the permissions to read and write for root only prevents non-root users from seeing the boot 
# parameters or changing them. Non-root users who read the boot parameters may be able to identify 
# weaknesses in security upon boot and be able to exploit them.
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
#   class security_baseline::rules::common::sec_grub2 {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_grub2 (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {

  if($enforce) {

    file { '/boot/grub2/grub.cfg':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
    }

    file { '/boot/grub2/user.cfg':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
    }

  } else {
    if(
      ($facts['security_baseline']['grub']['grub.cfg']['uid'] != 0) or
      ($facts['security_baseline']['grub']['grub.cfg']['gid'] != 0) or
      ($facts['security_baseline']['grub']['grub.cfg']['mode'] != 0600)
    ) {
      echo { 'grub-grub-cfg':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }

    if(
      ($facts['security_baseline']['grub']['user.cfg']['uid'] != 0) or
      ($facts['security_baseline']['grub']['user.cfg']['gid'] != 0) or
      ($facts['security_baseline']['grub']['user.cfg']['mode'] != 0600)
    ) {
      echo { 'grub-user-cfg':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
