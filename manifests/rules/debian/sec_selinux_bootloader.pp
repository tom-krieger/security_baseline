# @summary Ensure SELinux is not disabled in bootloader configuration (Scored)
#
# Configure SELINUX to be enabled at boot time and verify that it has not been overwritten by the grub boot parameters.
#
# Rationale:
# SELinux must be enabled at boot time in your grub configuration to ensure that the controls it provides are not overridden.
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
#   class security_baseline::rules::debian::sec_selinux_bootloader {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::debian::sec_selinux_bootloader (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    if($facts['operatingsystem'] == 'Debian') {
      if(
        ($facts['security_baseline']['selinux']['bootloader'] == false) or
        (!((has_key($facts, 'security_baseline')) and
          (has_key($facts['security_baseline'], 'selinux')) and
          (has_key($facts['security_baseline']['selinux'], 'bootloader'))))
      ) {
        exec { 'activate selinux':
          command => 'selinux-activate',
          path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          before  => Exec['selinux-grub-config'],
        }
      }
    }
    file_line { 'cmdline_definition':
      line   => 'GRUB_CMDLINE_LINUX_DEFAULT="quiet"',
      path   => '/etc/default/grub',
      match  => '^GRUB_CMDLINE_LINUX_DEFAULT',
      notify => Exec['selinux-grub-config'],
    }
    kernel_parameter { 'selinux':
      ensure => present,
      value  => '1',
      notify => Exec['selinux-grub-config']
    }
    kernel_parameter { 'security':
      ensure => present,
      value  => 'selinux',
      notify => Exec['selinux-grub-config']
    }
    kernel_parameter { 'enforcing':
      ensure => present,
      value  => '1',
      notify => Exec['selinux-grub-config']
    }
    exec {'selinux-grub-config':
      command     => 'update-grub',
      path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      refreshonly => true,
    }
  } else {
    if($facts['security_baseline']['selinux']['bootloader'] == false) {
      echo { 'bootloader-selinux':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
