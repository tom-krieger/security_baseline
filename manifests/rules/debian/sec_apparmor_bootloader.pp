# @summary 
#    Ensure AppArmor is not disabled in bootloader configuration (Scored)
#
# Description:
# Configure AppArmor to be enabled at boot time and verify that it has not been overwritten 
# by the bootloader boot parameters.
# 
# Rationale:
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
#   class security_baseline::rules::debian::sec_apparmor_bootloader {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::debian::sec_apparmor_bootloader (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    file_line { 'cmdline_definition':
      line   => 'GRUB_CMDLINE_LINUX_DEFAULT="quiet"',
      path   => '/etc/default/grub',
      match  => '^GRUB_CMDLINE_LINUX_DEFAULT',
      notify => Exec['apparmor-grub-config']
    }

    exec {'apparmor-grub-config':
      command     => 'update-grub',
      path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      refreshonly => true,
    }
  } else {
    if($facts['security_baseline']['apparmor']['bootloader'] == false) {
      echo { 'bootloader-apparmor':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
