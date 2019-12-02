# @summary
#    Ensure SELinux is installed (Scored)
#
# SELinux provides Mandatory Access Controls.
#
# Rationale:
# Without a Mandatory Access Control system installed only the default Discretionary Access Control system 
# will be available.
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
#   class security_baseline::rules::redhat::sec_selinux_state {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_selinux (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if $facts['os']['name'].downcase() != 'sles' {

    if($enforce) {

      package { 'libselinux':
        ensure => present,
      }

    } else {

      if($facts['security_baseline']['packages_installed']['libselinux'] == false) {

        echo { 'selinux-pkg':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }

      }
    }
  }
}
