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
# @param log_level
#    The log_level for the above message
#
# @example
#   class security_baseline::rules::common::sec_prelink {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_prelink (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    if($facts['security_baseline']['packages_installed']['prelink'] and ($::osfamily != 'Suse')) {
      if $facts['os']['name'].downcase() == 'sles' {
        $action = 'absent'
      } else {
        $action = 'purged'
      }
      package { 'prelink':
        ensure => $action,
      }
    }

  } else {

    if($facts['security_baseline']['packages_installed']['prelink']) {

      echo { 'prelink':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }

    }
  }
}