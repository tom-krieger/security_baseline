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
# @param loglevel
#    The loglevel for the above message
#
# @example
#   class security_baseline::rules::sec_selinux_state {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_selinux (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    package { 'libselinux':
      ensure => present,
    }

  } else {

    if($::selinux_pkg == false) {

      echo { 'selinux-pkg':
        message  => $message,
        loglevel => $loglevel,
      }

    }
  }
}
