# @summary
#    Ensure the SELinux state is enforcing (Scored)
#
# Set SELinux to enable when the system is booted.
#
# Rationale:
# SELinux must be enabled at boot time in to ensure that the controls it provides are in effect at all times.
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
#   class security_baseline::rules::common::sec_selinux_state {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_selinux_state (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {
    if(!defined(File['/etc/selinux/config'])) {
      file { '/etc/selinux/config':
        ensure => present,
        owner  => 'root',
        group  => 'root',
        mode   => '0644',
      }
    }
    file_line { 'selinux_enforce':
      path     => '/etc/selinux/config',
      line     => 'SELINUX=enforcing',
      match    => 'SELINUX=',
      multiple => true,
    }
  } else {
    if($::selinux_config_mode != 'enforcing') {

      echo { 'selinux_enforce':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
