# @summary
#    Ensure prelink is disabled (Scored)
#
# prelinkis a program that modifies ELF shared libraries and ELF dynamically linked binaries 
# in such a way that the time needed for the dynamic linker to perform relocations at startup 
# significantly decreases.
#
# Rationale:
# The prelinking feature can interfere with the operation of AIDE, because it changes binaries. 
# Prelinking can also increase the vulnerability of the system if a malicious user is able to 
# compromise a common library such as libc.
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
#   class security_baseline::rules::sec_prelink {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_prelink (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    package { 'prelink':
      ensure => purged,
    }

  } else {

    if($::prelink_pkg) {

      notify { 'prelink':
        message  => $message,
        loglevel => $loglevel,
      }

    }
  }
}
