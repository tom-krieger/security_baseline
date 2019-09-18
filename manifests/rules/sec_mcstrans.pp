# @summary 
#    Ensure the MCS Translation Service (mcstrans) is not installed (Scored)
#
# The mcstransd daemon provides category label information to client processes requesting 
# information. The label translations are defined in /etc/selinux/targeted/setrans.conf
#
# Rationale:
# Since this service is not used very often, remove it to reduce the amount of potentially 
# vulnerable code running on the system.
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
#   class security_baseline::rules::sec_mcstrans {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_mcstrans (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    package { 'mcstrans':
      ensure => purged,
    }

  } else {

    if($facts['packages_installed']['mcstrans_pkg']) {
      echo { 'mcstrans':
        message   => $message,
        log_level => $log_level,
        withpath  => false,
      }

    }

  }
}
